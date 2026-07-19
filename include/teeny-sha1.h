#ifndef UWSC_TEENY_SHA1_H
#define UWSC_TEENY_SHA1_H

#include <stddef.h>
#include <stdint.h>

int uwsc_sha1digest(uint8_t *digest, char *hexdigest, const uint8_t *data, size_t databytes);

#endif /* UWSC_TEENY_SHA1_H */
