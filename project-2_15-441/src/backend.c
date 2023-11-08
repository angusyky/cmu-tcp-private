/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define PRINT_DBG true

/**
 * Create simple packet with no payload (for handshake and listener ACKs)
 */
uint8_t *create_simple_packet(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                              uint8_t flags) {
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;
  uint16_t adv_window =
      MAX_NETWORK_BUFFER -
      ((sock->window.next_seq_expected - 1) - sock->window.last_byte_read);
  uint16_t payload_len = 0;
  uint8_t *payload = NULL;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  return create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                       ext_len, ext_data, payload, payload_len);
}

/**
 * Create a packet with payload
 */
uint8_t *create_data_packet(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                            uint16_t payload_len, uint8_t *payload) {
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window =
      MAX_NETWORK_BUFFER -
      ((sock->window.next_seq_expected - 1) - sock->window.last_byte_read);
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint8_t flags = ACK_FLAG_MASK;
  return create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                       ext_len, ext_data, payload, payload_len);
}

/**
 * Retransmit missing segment
 */
void retransmit(cmu_socket_t *sock, uint32_t seq_start) {
  queue_t *q = &sock->window.sent_queue;
  for (uint32_t i = 0; i < q->count; ++i) {
    window_slot_t *slot = &q->arr[get_arr_idx(q, i)];
    if (slot->seq_start == seq_start) {
      sendto(sock->socket, slot->packet,
             get_plen((cmu_tcp_header_t *)slot->packet), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      print_packet(slot->packet, false);
      slot->time_sent = time_ms();
      return;
    }
  }
}

/**
 * Check if packet has the right fields for its type
 */
bool validate_packet(cmu_socket_t *sock, uint8_t *packet) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)packet;
  uint8_t recv_flags = get_flags(hdr);
  switch (recv_flags) {
    case SYN_FLAG_MASK:
      if (sock->type != TCP_LISTENER) return false;
      if (sock->handshake_state != LISTEN) return false;
      if (get_hlen(hdr) != sizeof(cmu_tcp_header_t)) return false;
      if (get_plen(hdr) != get_hlen(hdr)) return false;
      if (get_payload_len(packet) != 0) return false;
      break;
    case SYN_FLAG_MASK | ACK_FLAG_MASK:
      if (sock->type != TCP_INITIATOR) return false;
      if (get_hlen(hdr) != sizeof(cmu_tcp_header_t)) return false;
      if (get_plen(hdr) != get_hlen(hdr)) return false;
      if (get_payload_len(packet) != 0) return false;
      if (sock->handshake_state != ESTABLISHED &&
          get_ack(hdr) != sock->window.last_ack_received + 1)
        return false;
      break;
    case ACK_FLAG_MASK:
      if (sock->type == TCP_INITIATOR && sock->handshake_state != ESTABLISHED)
        return false;
      if (sock->type == TCP_LISTENER && sock->handshake_state != ESTABLISHED &&
          get_ack(hdr) != sock->window.last_ack_received + 1)
        return false;
      if (get_ack(hdr) == 0) return false;
      break;
    default:
      // INVALID FLAG
      return false;
  }
  return true;
}

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t recv_flags = get_flags(hdr);

  if (!validate_packet(sock, pkt)) return;
  print_packet(pkt, true);

  switch (recv_flags) {
    case SYN_FLAG_MASK: {
      sock->handshake_state = SYN_RECV;
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      sock->window.last_byte_read = get_seq(hdr);
      break;
    }

    case (SYN_FLAG_MASK | ACK_FLAG_MASK): {
      // Record last ACK from Listener
      uint32_t recv_ack = get_ack(hdr);
      if (after(recv_ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = recv_ack;
      }

      // Initialize sequence number from Listener
      if (sock->handshake_state != ESTABLISHED) {
        sock->window.next_seq_expected = get_seq(hdr) + 1;
        sock->window.last_byte_read = get_seq(hdr);
      }

      // Respond with basic ACK
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint8_t flags = ACK_FLAG_MASK;
      uint8_t *packet = create_simple_packet(sock, seq, ack, flags);
      sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      print_packet(packet, false);
      free(packet);

      break;
    }

    case ACK_FLAG_MASK: {
      uint32_t recv_ack = get_ack(hdr);

      // Handle handshake / non-data ACKs.
      if (get_plen(hdr) == get_hlen(hdr)) {
        // Record receiver advertised window
        sock->window.recv_size = get_advertised_window(hdr);

        // New ACK received, record it and increase CWND
        if (after(recv_ack, sock->window.last_ack_received)) {
          sock->window.last_ack_received = recv_ack;
          switch (sock->reno_state) {
            case SLOW_START:
              sock->window.cwnd = sock->window.cwnd + MSS;
              sock->window.dup_ack_count = 0;
              if (sock->window.cwnd >= sock->window.ssthresh) {
                sock->reno_state = CONGESTION_AVOIDANCE;
              }
              break;
            case CONGESTION_AVOIDANCE:
              sock->window.dup_ack_count = 0;
              sock->window.cwnd =
                  sock->window.cwnd + ((MSS * MSS) / sock->window.cwnd);
              break;
            case FAST_RECOVERY:
              sock->window.cwnd = sock->window.ssthresh;
              sock->reno_state = CONGESTION_AVOIDANCE;
              break;
          }
          // Clear out ACKed packets from our linked list
          window_slot_t *slot;
          queue_t *q = &sock->window.sent_queue;
          while ((slot = front(q)) != NULL) {
            if (has_been_acked(sock, slot->seq_start)) {
              free(slot->packet);
              dequeue(q);
            } else {
              break;
            }
          }
        }
        // Dup ACK received, update cwnd as necessary
        else if (recv_ack == sock->window.last_ack_received) {
          switch (sock->reno_state) {
            case SLOW_START:
            case CONGESTION_AVOIDANCE:
              ++sock->window.dup_ack_count;
              if (sock->window.dup_ack_count == 3) {
                sock->window.ssthresh = sock->window.cwnd / 2;
                sock->window.cwnd = sock->window.ssthresh + 3 * MSS;
                sock->reno_state = FAST_RECOVERY;
                retransmit(sock, sock->window.last_ack_received);
              }
              break;
            case FAST_RECOVERY:
              sock->window.cwnd += MSS;
              break;
          }
        }
        break;
      }

      // Handle DATA ACKs.
      if (after(recv_ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = recv_ack;
      }

      // If this is the next expected segment, store in socket recv buffer
      uint32_t recv_seq = get_seq(hdr);
      if (recv_seq == sock->window.next_seq_expected) {
        uint16_t recv_payload_len = get_payload_len(pkt);
        sock->window.next_seq_expected = recv_seq + recv_payload_len;
        uint8_t *recv_payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + recv_payload_len);
        memcpy(sock->received_buf + sock->received_len, recv_payload,
               recv_payload_len);
        sock->received_len += recv_payload_len;
      }

      // Respond with basic ACK
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint8_t flags = ACK_FLAG_MASK;
      uint8_t *packet = create_simple_packet(sock, seq, ack, flags);
      sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      print_packet(packet, false);
      free(packet);
      break;
    }

    default:
      return;
  }
  print_state(sock);
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and
 * then reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data.
 * Check `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  int sockfd = sock->socket;
  queue_t *q = &sock->window.sent_queue;
  window_slot_t *slot;

  while (buf_len != 0 || q->count > 0) {
    check_for_data(sock, NO_WAIT);

    // Check for timeout.
    uint32_t w_size = MIN((uint32_t)sock->window.recv_size, sock->window.cwnd);
    uint32_t w_max = sock->window.last_ack_received + w_size;
    for (uint32_t i = 0; i < q->count; ++i) {
      slot = &q->arr[get_arr_idx(q, i)];
      if (!before(slot->seq_end, w_max)) break;
      if (time_ms() - slot->time_sent >= DEFAULT_TIMEOUT) {
        sock->reno_state = SLOW_START;
        sock->window.ssthresh = sock->window.cwnd / 2;
        sock->window.cwnd = MSS;
        sock->window.dup_ack_count = 0;
        retransmit(sock, slot->seq_start);
        break;
      }
    }

    if (buf_len == 0) continue;

    // Transmit new segments as allowed
    w_size = MIN((uint32_t)sock->window.recv_size, sock->window.cwnd);
    w_max = sock->window.last_ack_received + w_size;
    uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);
    uint32_t new_highest_byte = sock->window.highest_byte_sent + payload_len;

    // Send packet if there is space
    while (buf_len > 0 && before(new_highest_byte, w_max)) {
      uint32_t seq = sock->window.highest_byte_sent + 1;
      uint32_t ack = sock->window.next_seq_expected;
      msg = create_data_packet(sock, seq, ack, payload_len, data_offset);
      sendto(sockfd, msg, sizeof(cmu_tcp_header_t) + payload_len, 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      print_packet(msg, false);

      // Add sent packet to data structures
      data_offset += payload_len;
      buf_len -= payload_len;
      sock->window.highest_byte_sent = new_highest_byte;
      enqueue(q, msg, seq, new_highest_byte, time_ms());

      // Try next segment
      payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);
      new_highest_byte = sock->window.highest_byte_sent + payload_len;
    }
  }
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  tcp_handshake(sock);

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}

/**
 * Perform TCP handshake depending on role
 */
void tcp_handshake(cmu_socket_t *sock) {
  while (sock->handshake_state != ESTABLISHED) {
    switch (sock->type) {
      case TCP_INITIATOR: {
        // Initiator sends SYN with seq/x = rand()
        uint32_t initial_seq = get_rand_seq_num();
        sock->window.last_ack_received = initial_seq;
        sock->window.highest_byte_sent = initial_seq;
        sock->window.next_seq_expected = 0;
        uint32_t seq = sock->window.last_ack_received;
        uint32_t ack = sock->window.next_seq_expected;
        uint8_t flags = SYN_FLAG_MASK;
        uint8_t *packet = create_simple_packet(sock, seq, ack, flags);

        // Retransmit until SYN-ACK is received
        while (1) {
          sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
                 (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
          print_packet(packet, false);
          check_for_data(sock, TIMEOUT);
          if (has_been_acked(sock, initial_seq)) {
            sock->handshake_state = ESTABLISHED;
            free(packet);
            break;
          }
        }
        break;
      }

      case TCP_LISTENER: {
        while (sock->handshake_state == LISTEN) {
          check_for_data(sock, TIMEOUT);
        }

        if (sock->handshake_state == SYN_RECV) {
          // Listener sends SYN-ACK with seq/y = rand() and ack = x + 1
          uint32_t initial_seq = get_rand_seq_num();
          sock->window.last_ack_received = initial_seq;
          sock->window.highest_byte_sent = initial_seq;
          uint32_t seq = sock->window.last_ack_received;
          uint32_t ack = sock->window.next_seq_expected;
          uint8_t flags = SYN_FLAG_MASK | ACK_FLAG_MASK;
          uint8_t *packet = create_simple_packet(sock, seq, ack, flags);

          // Retransmit until ACK is received
          while (1) {
            sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
                   (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
            print_packet(packet, false);
            check_for_data(sock, TIMEOUT);
            if (has_been_acked(sock, initial_seq)) {
              sock->handshake_state = ESTABLISHED;
              free(packet);
              break;
            }
          }
        }
      }
    }
  }
}

/************************************************************************
 *
 * UTILS
 *
 *************************************************************************/

/**
 * Print received packet
 */
void print_packet(uint8_t *packet, bool is_recv) {
  if (!PRINT_DBG) return;
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)packet;
  uint8_t recv_flags = get_flags(hdr);
  char *action = is_recv ? "Received" : "Sent";

  switch (recv_flags) {
    case SYN_FLAG_MASK:
      printf("%s SYN (seq = %d)\n", action, get_seq(hdr));
      break;
    case SYN_FLAG_MASK | ACK_FLAG_MASK:
      printf("%s SYN-ACK (seq = %d, ack = %d)\n", action, get_seq(hdr),
             get_ack(hdr));
      break;
    case ACK_FLAG_MASK:
      if (get_payload_len(packet) != 0) {
        printf("%s DATA (seq = %d, ack = %d, payload = %d, plen = %d)\n",
               action, get_seq(hdr), get_ack(hdr), get_payload_len(packet),
               get_plen(hdr));
      } else {
        printf("%s ACK (seq = %d, ack = %d)\n", action, get_seq(hdr),
               get_ack(hdr));
      }
      break;
    default:
      return;
      printf("INVALID FLAG\n");
  }
}

/**
 * Print state
 */
void print_state(cmu_socket_t *sock) {
  if (!PRINT_DBG) return;
  printf("[");
  //  printf(" LAST_ACK: %d ", sock->window.last_ack_received);
  //  printf(" NEXT_SEQ: %d ", sock->window.next_seq_expected);
  //  printf(" HIGHEST_BYTE_SENT: %d ", sock->window.highest_byte_sent);
  printf(" TCP_STATE: %d ", sock->reno_state);
  printf(" CWND: %d ", sock->window.cwnd);
  //  printf(" DUP_ACK_COUNT: %d ", sock->window.dup_ack_count);
  printf(" SSTHRESH: %d ", sock->window.ssthresh);
  printf(" RECV_WINDOW: %hu ", sock->window.recv_size);
  printf(" SENDING_WINDOW: %hu ",
         MIN(sock->window.recv_size, sock->window.cwnd));
  //  printf(" SOCK_RECV_LEN: %d ", sock->received_len);
  printf(" SOCK_SEND_LEN: %d ", sock->sending_len);
  printf("]\n");
}

/**
 * Print window packet queue
 */
void print_queue(queue_t *q) {
  if (!PRINT_DBG) return;
  printf("Queue (HEAD: %d, COUNT: %d)\n", q->head, q->count);
  printf("[\n");
  for (uint32_t i = 0; i < q->count; ++i) {
    window_slot_t *wp = &q->arr[get_arr_idx(q, i)];
    printf("(time_sent: %d, plen) ", wp->time_sent);
    print_packet(wp->packet, false);
    printf("\n");
  }
  printf("]\n");
}

/**
 * Get time in ms
 */
uint32_t time_ms() {
  struct timespec time;
  timespec_get(&time, TIME_UTC);
  return ((uint32_t)time.tv_sec) * 1000 + ((uint32_t)time.tv_nsec) / 1000000;
}

/**
 * Get random integer
 */
uint32_t get_rand_seq_num() {
  struct timespec nanos;
  clock_gettime(CLOCK_MONOTONIC, &nanos);
  srand(nanos.tv_nsec);
  return rand();
}
