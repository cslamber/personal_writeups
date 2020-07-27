#include "filters.h"

#define MAT_SIZE 3

const int matrix[MAT_SIZE][MAT_SIZE] = {{-1, -1, -1},
                                        {-1,  10, -1},
                                        {-1, -1, -1}};

int constrain(int x, int min, int max) {
    if(x < min) return min;
    if(x > max) return max;
    return x;
}

//https://processing.org/tutorials/pixels/
static color_t convolution(image_t *img, int x, int y) {

    color_t ret;

    int i, j;

    int r = 0, g = 0, b = 0;
    int offset = MAT_SIZE / 2;

    for(i = 0; i < MAT_SIZE; i++) {
        for(j = 0; j < MAT_SIZE; j++) {
            int xloc, yloc;

            xloc = x + j - offset;
            yloc = y + i - offset;

            if(xloc < 0 || xloc > WIDTH + 1)    xloc = x;
            if(yloc < 0 || yloc > HEIGHT + 1)   yloc = y;

            r += img->pixels[yloc][xloc].r * matrix[i][j];
            g += img->pixels[yloc][xloc].g * matrix[i][j];
            b += img->pixels[yloc][xloc].b * matrix[i][j];
        }
    }

    ret.r = (uint8_t)constrain(r, 0, 255);
    ret.g = (uint8_t)constrain(g, 0, 255);
    ret.b = (uint8_t)constrain(b, 0, 255);

    return ret;
}

#define BUFLEN MAT_SIZE

void sharpen(image_t *img) {

    unsigned x, y;

    color_t buffer[BUFLEN][WIDTH];

    for(y = 0; y < HEIGHT; y++) {
        for(x = 0; x < WIDTH; x++) {

            if(y >= BUFLEN) {
                img->pixels[y - BUFLEN][x] = buffer[y % BUFLEN][x];    
            }

            buffer[y % BUFLEN][x] = convolution(img, x, y);
        }
    }

    for(y = 0; y < BUFLEN; y++) {
        for(x = 0; x < WIDTH; x++) {
            img->pixels[HEIGHT - BUFLEN - 1 + y][x] = buffer[y][x];
        }
    }
}

#include "emojis.h"

typedef struct Emoji {
    unsigned w, h;
    color_t *pixels;
} emoji_t;

#define NUM_EMOJIS 4

const static emoji_t emojis[NUM_EMOJIS] = {
    {25, 25, emoji_gottem},
    {20, 20, emoji_b},
    {20, 20, emoji_cry},
    {15, 15, emoji_fire}
};

void emoji_draw(emoji_t *e, image_t *img, unsigned x, unsigned y) {
    unsigned i, j;

    for(i = 0; i < e->h && y + i < HEIGHT; i++) {
        for(j = 0; j < e->w && x + j < WIDTH; j++) {
            uint8_t r, g, b;

            r = e->pixels[i * e->w + j].r;
            g = e->pixels[i * e->w + j].g;
            b = e->pixels[i * e->w + j].b;

            //alpha pixel
            if(r == 0 && g == 255 && b == 0)
                continue;

            img->pixels[y + i][x + j].r = r;
            img->pixels[y + i][x + j].g = g;
            img->pixels[y + i][x + j].b = b;
        }
    }
}

void emoji(image_t *img) {
    unsigned i;

    srandom(rtc_Time());

    for(i = 0; i < NUM_EMOJIS + 1; i++) {
        int x, y;
        emoji_t *e;

        e = i < NUM_EMOJIS ? &emojis[i] : &emojis[randInt(0, NUM_EMOJIS - 1)];

        x = randInt(0, WIDTH - e->w);
        y = randInt(0, HEIGHT - e->h);

        emoji_draw(e, img, x, y);
    }


}