#ifndef PROJECT_2_15_441_INC_QUEUE_H_
#define PROJECT_2_15_441_INC_QUEUE_H_

#define N_ITEMS 65535

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint32_t seq_start;
  uint32_t seq_end;
  uint32_t time_sent;
  uint8_t *packet;
} window_slot_t;

typedef struct {
  window_slot_t arr[N_ITEMS];
  uint32_t head;
  uint32_t count;
} queue_t;

window_slot_t *front(queue_t *q);
window_slot_t *back(queue_t *q);
int enqueue(queue_t *q, uint8_t *packet, uint32_t seq_start, uint32_t seq_end,
            uint32_t time_sent);
int dequeue(queue_t *q);
uint32_t get_arr_idx(queue_t *q, uint32_t i);

#endif  // PROJECT_2_15_441_INC_QUEUE_H_
