// cardparse - a tiny contact card (.card) parser.
//
// Reads a simple line based ".card" file and prints the parsed record.
// A few directives let a card store binary data and export itself to disk.
//
// This is a small sample application meant to be used as a fuzzing target.
// It is written in a deliberately naive style and contains memory safety
// and input validation bugs. It is not meant for production use.

#include "cardparse.h"

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

// Strip a trailing newline (and carriage return) in place.
void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

// Copy a value into a destination buffer, truncating it to fit.
static void copy_field(char *dst, size_t capacity, const char *value) {
    if (capacity == 0) {
        return;
    }
    size_t length = 0;
    while (length + 1 < capacity && value[length] != '\0') {
        dst[length] = value[length];
        ++length;
    }
    dst[length] = '\0';
}

// Copy a field value into the standard 64-byte field buffer.
void set_field(char *dst, const char *value) {
    copy_field(dst, 64, value);
}

// Decode a "data:<len>:<bytes>" record into a small working buffer.
// The length is read from the record and trusted as-is.
void load_data(const char *spec) {
    char buf[32];
    long len = strtol(spec, nullptr, 10);
    const char *payload = strchr(spec, ':');
    if (!payload) {
        return;
    }
    payload++; // skip the ':' separator
    for (long i = 0; i < len && i < static_cast<long>(sizeof(buf)) &&
                    payload[i] != '\0'; i++) {
        buf[i] = payload[i];
    }
    printf("loaded %ld bytes of data\n", len);
}

// Export only to a plain filename in the current directory.
void save_card(const Card *c, const char *path) {
    if (!path || !*path || strchr(path, '/') || strchr(path, '\\') ||
        strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
        fprintf(stderr, "invalid card output filename\n");
        return;
    }
    // Do not let an existing symbolic link redirect the export elsewhere.
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0666);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s for writing\n", path);
        return;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        fprintf(stderr, "cannot open %s for writing\n", path);
        return;
    }
    fprintf(f, "name=%s\ntitle=%s\nnote=%s\n", c->name, c->title, c->note);
    fclose(f);
    printf("saved card to %s\n", path);
}

// Parse a stream of "key:value" lines into a single card.
void parse_stream(FILE *in) {
    Card card;
    memset(&card, 0, sizeof(card));

    char line[1024];
    while (fgets(line, sizeof(line), in)) {
        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char *sep = strchr(line, ':');
        if (!sep) {
            continue;
        }
        *sep = '\0';
        const char *key = line;
        const char *value = sep + 1;

        if (strcmp(key, "name") == 0) {
            set_field(card.name, value);
        } else if (strcmp(key, "title") == 0) {
            set_field(card.title, value);
        } else if (strcmp(key, "note") == 0) {
            copy_field(card.note, sizeof(card.note), value);
        } else if (strcmp(key, "data") == 0) {
            load_data(value);
        } else if (strcmp(key, "save") == 0) {
            save_card(&card, value);
        }
    }

    printf("card: name=%s title=%s\n", card.name, card.title);
}
