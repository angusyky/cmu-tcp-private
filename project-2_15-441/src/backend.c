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
#include <sys/types.h>
#include <time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
/**
 * Get random integer
 */
int get_rand_seq_num() {
  struct timespec nanos;
  clock_gettime(CLOCK_MONOTONIC, &nanos);
  srand(nanos.tv_nsec);
  return rand();
}

/**
 * Create simple packet with no payload
 */
uint8_t *create_default_packet(cmu_socket_t *sock, uint8_t flags) {
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;
  uint16_t adv_window = 1;
  uint16_t payload_len = 0;
  uint8_t *payload = NULL;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  return create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                       ext_len, ext_data, payload, payload_len);
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

  switch (recv_flags) {
    case SYN_FLAG_MASK: {
      // Listener responds using SYN-ACK with seq/y = rand() and ack = x + 1
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      sock->window.last_ack_received = get_rand_seq_num();
      uint8_t *response_packet =
          create_default_packet(sock, SYN_FLAG_MASK | ACK_FLAG_MASK);
      sendto(sock->socket, response_packet, sizeof(cmu_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      free(response_packet);
      break;
    }

    case (SYN_FLAG_MASK | ACK_FLAG_MASK): {
      // Initiator records last seq num received by Listener
      uint32_t recv_ack = get_ack(hdr);
      if (after(recv_ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = recv_ack;
      }

      // Initiator responds using ACK with ack = y + 1
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      uint8_t *response_packet = create_default_packet(sock, ACK_FLAG_MASK);
      sendto(sock->socket, response_packet, sizeof(cmu_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      free(response_packet);
      break;
    }

    case ACK_FLAG_MASK: {
      // Receiver records last seq num received by other side
      uint32_t recv_ack = get_ack(hdr);
      if (after(recv_ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = recv_ack;
      }

      // Ignore handshake / non-data ACKs
      if (get_plen(hdr) == get_hlen(hdr)) {
        break;
      }

      // If this is the next expected segment, store in socket recv buffer
      uint32_t recv_seq = get_seq(hdr);
      if (recv_seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = recv_seq + get_payload_len(pkt);
        uint16_t recv_payload_len = get_payload_len(pkt);
        uint8_t *recv_payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + recv_payload_len);
        memcpy(sock->received_buf + sock->received_len, recv_payload,
               recv_payload_len);
        sock->received_len += recv_payload_len;
      }

      // Send ACK to acknowledge receipt of data packet
      uint8_t *response_packet = create_default_packet(sock, ACK_FLAG_MASK);
      sendto(sock->socket, response_packet, sizeof(cmu_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      free(response_packet);
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
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

  // Initiator sends SYN with seq/x = rand() until we receive SYN-ACK
  uint32_t initial_seq = get_rand_seq_num();
  sock->window.last_ack_received = initial_seq;
  sock->window.next_seq_expected = 0;
  msg = create_default_packet(sock, SYN_FLAG_MASK);
  while (1) {
    sendto(sockfd, msg, sizeof(cmu_tcp_header_t), 0,
           (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
    check_for_data(sock, TIMEOUT);
    if (has_been_acked(sock, initial_seq)) {
      free(msg);
      break;
    }
  }

  // Handshake complete. Now send data in TCP windows.
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               sizeof(sock->conn));
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          free(msg);
          break;
        }
      }

      data_offset += payload_len;
    }
  }
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

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
