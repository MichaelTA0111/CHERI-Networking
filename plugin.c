#include "plugin.h"
#include "consumer.h"


static Consumer cons1, cons2;

void plugin_consumer_interaction(int consumer_id)
{
    if (consumer_id == 0) {
        consumer_increment_counter(&cons1);
    } else if (consumer_id == 1) {
        consumer_increment_counter(&cons2);
    }

    return;
}

unsigned long plugin_get_consumer_counter(int consumer_id)
{
    if (consumer_id == 1) {
        return cons1.counter;
    } else if (consumer_id == 2) {
        return cons2.counter;
    }

    return -1;
}

