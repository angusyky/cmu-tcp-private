#include "queue.h"

#include <stdio.h>

window_packet_t *front(queue_t *q) {
  if (q->count == 0) {
    return NULL;
  }
  return &q->arr[q->head];
}

window_packet_t *back(queue_t *q) {
  if (q->count == 0) {
    return NULL;
  }
  uint32_t tail_idx = (q->head + q->count - 1) % N_ITEMS;
  return &q->arr[tail_idx];
}

int enqueue(queue_t *q, uint8_t *packet, uint32_t seq, uint32_t time_sent) {
  uint32_t new_idx = (q->head + q->count) % N_ITEMS;
  if (q->count == N_ITEMS) {
    printf("Queue full: %d / %d\n", q->count, N_ITEMS);
    return -1;
  } else {
    q->count++;
    window_packet_t *new_packet = &q->arr[new_idx];
    new_packet->packet = packet;
    new_packet->seq_num = seq;
    new_packet->time_sent = time_sent;
    return 0;
  }
}

int dequeue(queue_t *q) {
  if (q->count == N_ITEMS) {
    printf("Queue full\n");
    return -1;
  } else {
    q->count--;
    q->head = (q->head + 1) % N_ITEMS;
    return 0;
  }
}

uint32_t get_arr_idx(queue_t *q, uint32_t i) { return (q->head + i) % N_ITEMS; }
