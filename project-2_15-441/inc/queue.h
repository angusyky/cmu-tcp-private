#ifndef TCP_QUEUE_H_
#define TCP_QUEUE_H_

#define N_ITEMS 65537

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint32_t seq_num;
  uint32_t time_sent;
  uint8_t *packet;
} window_packet_t;

typedef struct {
  window_packet_t arr[N_ITEMS];
  int head;
  int count;
} queue_t;

window_packet_t *front(queue_t *q);
window_packet_t *back(queue_t *q);
int enqueue(queue_t *q, uint8_t *packet, uint32_t seq, uint32_t time_sent);
int dequeue(queue_t *q);
int get_arr_idx(queue_t *q, int i);

#endif  // TCP_QUEUE_H_
