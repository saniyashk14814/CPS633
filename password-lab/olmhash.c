/*
 * olmhash.c -- Part 1: OLMHash password scheme (CPS 633)
 *
 * Maintains a (user id, password hash) table in a text file.
 * On launch it prompts for a user id:
 *   - unknown id  -> create account (prompt + hash a new password)
 *   - known id    -> verify old password by hash, then change it,
 *                    locking the account after MAX_ATTEMPTS failures.
 */

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define MAX_USERS     100
#define MAX_ATTEMPTS  3        /* the spec's security parameter n */

/* One row of the password table. */
struct user {
    char uid[64];
    char hex[25];              /* 24 hex chars + '\0' */
};

struct user users[MAX_USERS];  /* in-memory copy of the table */
int num_users = 0;

/********************* E function *************************/
/* DES replacement cipher (supplied by the lab, verbatim).
 * Takes 4 bytes from *in and writes 4 bytes to *out. */
void E(char *in, char *out)
{
    out[0]=(in[0]&0x80)^(((in[0]>>1)&0x7F)^((in[0])&0x7F));
    out[1]=((in[1]&0x80)^((in[0]<<7)&0x80))^(((in[1]>>1)&0x7F)^((in[1])&0x7F));
    out[2]=((in[2]&0x80)^((in[1]<<7)&0x80))^(((in[2]>>1)&0x7F)^((in[2])&0x7F));
    out[3]=((in[3]&0x80)^((in[2]<<7)&0x80))^(((in[3]>>1)&0x7F)^((in[3])&0x7F));
}

/* Hash a password: pad/truncate to 12 chars, uppercase, split into
 * three 4-byte blocks, and run each block through E(). */
void olmhash(char *password, unsigned char *hash) {
    char block[12] = {0};                         /* zero = '\0' padding */
    for (int i = 0; i < 12 && password[i] != '\0'; i++)
        block[i] = toupper((unsigned char)password[i]);

    E(block,     (char *)hash);
    E(block + 4, (char *)hash + 4);
    E(block + 8, (char *)hash + 8);
}

/* Convert the 12-byte hash to a 24-char hex string. */
void hash_to_hex(unsigned char *hash, char *hex) {
    for (int i = 0; i < 12; i++)
        sprintf(hex + i * 2, "%02x", hash[i]);
}

/* Read a line of input and strip the trailing newline. */
void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\n")] = '\0';
}

/* Load the table from disk (missing file = empty table). */
void load_table(void) {
    FILE *fp = fopen("olmhash_table.txt", "r");
    if (fp == NULL) return;
    while (num_users < MAX_USERS &&
           fscanf(fp, "%63s %24s", users[num_users].uid, users[num_users].hex) == 2)
        num_users++;
    fclose(fp);
}

/* Write the whole in-memory table back to disk. */
void save_table(void) {
    FILE *fp = fopen("olmhash_table.txt", "w");
    if (fp == NULL) {
        printf("Error: cannot write table file\n");
        return;
    }
    for (int i = 0; i < num_users; i++)
        fprintf(fp, "%s %s\n", users[i].uid, users[i].hex);
    fclose(fp);
}

/* Return the index of uid in the table, or -1 if not found. */
int find_user(char *uid) {
    for (int i = 0; i < num_users; i++)
        if (strcmp(users[i].uid, uid) == 0)
            return i;
    return -1;
}

/* Password rule: letters and digits only, not empty. */
int valid_password(char *pw) {
    if (pw[0] == '\0')
        return 0;
    for (int i = 0; pw[i] != '\0'; i++)
        if (!isalpha((unsigned char)pw[i]) && !isdigit((unsigned char)pw[i]))
            return 0;
    return 1;
}

/* Prompt until a valid password is entered. */
void read_valid_password(char *prompt, char *password) {
    while (1) {
        printf("%s", prompt);
        read_line(password, 64);
        if (valid_password(password))
            return;
        printf("Password must use letters and digits only (no spaces or special characters).\n");
    }
}

int main(void) {
    char userid[64];
    char password[64];
    unsigned char hash[12];
    char hex[25];

    load_table();

    printf("Enter user id: ");
    read_line(userid, sizeof(userid));

    /* User-id rule: 4 to 31 characters. */
    if (strlen(userid) < 4 || strlen(userid) > 31) {
        printf("Invalid user id: must be 4 to 31 characters.\n");
        return 1;
    }

    int idx = find_user(userid);

    if (idx == -1) {
        /* New user: hash a new password and store it. */
        read_valid_password("New user. Enter a new password: ", password);

        olmhash(password, hash);
        hash_to_hex(hash, hex);

        strcpy(users[num_users].uid, userid);
        strcpy(users[num_users].hex, hex);
        num_users++;

        save_table();
        printf("Account created.\n");
    } else {
        /* Existing user: verify old password, up to MAX_ATTEMPTS tries. */
        int attempts = 0;
        int authenticated = 0;

        while (attempts < MAX_ATTEMPTS) {
            printf("Enter your old password: ");
            read_line(password, sizeof(password));

            olmhash(password, hash);
            hash_to_hex(hash, hex);

            if (strcmp(hex, users[idx].hex) == 0) {
                authenticated = 1;
                break;
            }

            attempts++;
            if (attempts < MAX_ATTEMPTS)
                printf("Incorrect password. Try again.\n");
        }

        if (authenticated) {
            /* Replace the stored hash with that of the new password. */
            read_valid_password("Authenticated. Enter your new password: ", password);

            olmhash(password, hash);
            hash_to_hex(hash, hex);

            strcpy(users[idx].hex, hex);
            save_table();
            printf("Password updated.\n");
        } else {
            printf("Too many unsuccessful attempt - your account is locked\n");
        }
    }

    return 0;
}
