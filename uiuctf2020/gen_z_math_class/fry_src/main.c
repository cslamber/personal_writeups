#include <fileioc.h>
#include <graphx.h>

#include "common.h"
#include "filters.h"

//Thanks to commandz on Cemetech for the magic numbers
const char* image_tokens[] = {"\x3C\x00", "\x3C\x01", "\x3C\x02",
							  "\x3C\x03", "\x3C\x04", "\x3C\x05",
							  "\x3C\x06", "\x3C\x07", "\x3C\x08",
							  "\x3C\x09"};
#define TI_IMAGE_TYPE 0x1A

filter default_filters[2] = {emoji, sharpen};

image_t *image_init(uint8_t *raw_data) {
	unsigned x, y;

	unsigned offset = 3;

	image_t *img;

	img = malloc(sizeof(image_t));

	//Thanks to PT_ on Cemetech for reversing this format
	for(y = 0; y < HEIGHT; y++) {
		for(x = 0; x < WIDTH; x++) {
			uint16_t word;

			word = *(uint16_t*)(raw_data + offset);

			img->pixels[HEIGHT - y - 1][x].r = (word >> 11) * 255 / 31;
			img->pixels[HEIGHT - y - 1][x].g = ((word >> 5) & 0x3F) * 255 / 63;
			img->pixels[HEIGHT - y - 1][x].b = (word & 0x1F) * 255 / 31;

			offset += 2;
		}

		//Last 2 bytes of each row are ignored for some reason
		offset += 2;
	}

	return img;
}

void image_draw(image_t *img) {

	unsigned x, y, i, j;
	unsigned x_offset, y_offset;

	x_offset = (LCD_WIDTH - WIDTH * RES) / 2;
	y_offset = (LCD_HEIGHT - HEIGHT * RES) / 2;

	for(y = 0; y < LCD_HEIGHT; y++) {
		for(x = 0; x < LCD_WIDTH; x++) {
			((uint16_t*)gfx_vram)[y * LCD_WIDTH + x] = 0;
		}
	}

	for(y = 0; y < HEIGHT; y++) {
		for(x = 0; x < WIDTH; x++) {
			uint8_t r, g, b;
			uint16_t color;

			r = img->pixels[y][x].r;
			g = img->pixels[y][x].g;
			b = img->pixels[y][x].b;

			color = (((r & 0xf8) << 8) + ((g & 0xfc) << 3) + (b >> 3));

			for(i = 0; i < RES; i++) {
				for(j = 0; j < RES; j++) {
					unsigned y_pix, x_pix;

					y_pix = y * RES + i + y_offset;
					x_pix = x * RES + j + x_offset;

					((uint16_t*)gfx_vram)[y_pix * LCD_WIDTH + x_pix] = color;
				}
			}

		}
	}

}

task_t *task_init() {
	unsigned i;
	ti_var_t img = 0;

	uint8_t *archived_data, *raw_data;
	uint16_t size;

	task_t *task;

	for(i = 0; i < 10 && !img; i++) {
		ti_CloseAll();
		img = ti_OpenVar(image_tokens[i], "r", TI_IMAGE_TYPE);
	}

	if(!img)
		return NULL;

	//The toolchain gives the wrong data offset for some reason.
	archived_data = (uint8_t*)ti_GetDataPtr(img) - 0x3C;

	size = *(uint16_t*)archived_data;
	raw_data = malloc(size);

	task = malloc(sizeof(task_t));

	task->filters.count = 2;
	task->filters.arr = default_filters;

	memcpy(raw_data, archived_data, SIZE);

	task->img = image_init(raw_data);

	return task;
}

void task_execute(task_t *task) {
	unsigned i;
	for(i = 0; i < task->filters.count; i++) {
		task->filters.arr[i](task->img);
	}
}

void task_cleanup(task_t *task) {
	free(task->img);
}

void main(void) {

	task_t *task;

	task = task_init();

	if(!task) {
		os_ClrHome();
		os_PutStrFull("No images found.");
	} else {
		task_execute(task);

		image_draw(task->img);

		task_cleanup(task);
		free(task);
	}

	while (!os_GetCSC());
}
