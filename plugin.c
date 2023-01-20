#include "plugin.h"
#include "consumer.h"


static Consumer cons1, cons2;

void plugin_consumer_interaction(int cons_num)
{
    if (cons_num == 1) {
        consumer_increment_counter(&cons1);
    } else if (cons_num == 2) {
        consumer_increment_counter(&cons2);
    }

    return;
}

unsigned long plugin_get_consumer_counter(int cons_num)
{
    if (cons_num == 1) {
        return cons1.counter;
    } else if (cons_num == 2) {
        return cons2.counter;
    }

    return -1;
}

