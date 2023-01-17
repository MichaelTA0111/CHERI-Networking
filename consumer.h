#ifndef CONSUMER_H
#define CONSUMER_H


/*
 * Structure to store the packet consumer information.
 */
typedef struct Consumer {
    unsigned long counter;
} Consumer;

/*
 * Increment the consumer counter.
 * @param consumer - Pointer to the consumer.
 */
void consumer_increment_counter(Consumer *consumer);

/*
 * Print consumer details.
 * @param consumer - Pointer to the consumer.
 */
void consumer_print_details(Consumer *consumer);


#endif

