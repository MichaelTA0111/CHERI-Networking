#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "consumer.h"


void consumer_increment_counter(Consumer *consumer)
{
    consumer->counter++;
}

void consumer_print_details(Consumer *consumer)
{
    printf("Counter = %lu\n", consumer->counter);
}

