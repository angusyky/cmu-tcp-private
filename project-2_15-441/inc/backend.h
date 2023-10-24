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
 * This file defines the function signatures for the CMU-TCP backend that should
 * be exposed. The backend runs in a different thread and handles all the socket
 * operations separately from the application.
 */

#ifndef PROJECT_2_15_441_INC_BACKEND_H_
#define PROJECT_2_15_441_INC_BACKEND_H_

#include <stdbool.h>
#include <stdint.h>

#include "cmu_tcp.h"

void print_packet(uint8_t* packet, bool is_recv);
void print_queue(queue_t* q);
void print_state(cmu_socket_t* sock);
uint32_t time_ms();
uint32_t get_rand_seq_num();

/**
 * Create a packet without payload (for handshake and listener ACKs)
 */
uint8_t* create_simple_packet(cmu_socket_t* sock, uint32_t seq, uint32_t ack,
                              uint8_t flags);

/**
 * Create a packet with payload
 */
uint8_t* create_data_packet(cmu_socket_t* sock, uint32_t seq, uint32_t ack,
                            uint16_t payload_len, uint8_t* payload);

/**
 * Check that packet is valid
 */
bool validate_packet(uint8_t* packet);

/**
 * Launches the CMU-TCP backend.
 *
 * @param in the socket to be used for backend processing.
 */
void* begin_backend(void* in);

#endif  // PROJECT_2_15_441_INC_BACKEND_H_
