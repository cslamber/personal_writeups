#ifndef COMMON_H_
#define COMMON_H_

#include <tice.h>
#include <debug.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

//All images have a constant size
#define SIZE    0x56e5
#define WIDTH   133
#define HEIGHT  83

#define RES     2

typedef struct Color {
    uint8_t r, g, b;
} color_t;

typedef struct Image {
    color_t pixels[HEIGHT][WIDTH];
} image_t;

typedef void (*filter)(image_t *);

typedef struct Task {
    image_t *img;

    struct {
        unsigned count;
        filter *arr;
    } filters;

} task_t;

#endif
