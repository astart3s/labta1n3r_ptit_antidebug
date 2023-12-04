#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <time.h>

char PTITCTF[] = "PTITCTF{";

void generateFlag(char *flag, const char *flagname, const char *rand1) {
    strcpy(flag, PTITCTF);
    strcat(flag, flagname);
    strcat(flag, "_");
    strcat(flag, rand1);
    strcat(flag, "}");
}

void swap(unsigned char *s, int i, int j);
char *rc4(unsigned char *key, unsigned char *data, size_t data_len);

void task2();
void task3();
void task4();
void task5();
void task6();
void task7();

int main() {
    char rand[] = "RANDOM1";
    char flaghead[] = "mainflag";
    char flag[100];

    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

        printf("Enter first flag: ");
        scanf("%s", user_input);

        // Compare user input with the generated flag
        if (strcmp(user_input, flag) == 0) {
            printf("First flag correct\n"); // Output when input matches the flag
        } else {
            printf("Incorrect. Try another flag\n"); // Prompt user to try again
        }

    task2();
    task3();
    task4();
    if ((*(volatile unsigned *)((unsigned)task5) & 0xff) == 0xcc) {
        printf("BREAKPOINT\n");
        exit(0);
    }
    task5();
    task6();
    task7();
    return 0;
}

void task2(){
    DIR *proc_dir;
    struct dirent *entry;

    if ((proc_dir = opendir("/proc")) == NULL) {
        perror("Error opening /proc directory");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (atoi(entry->d_name) != 0) {
            char cmd_path[512]; // Increased buffer size
            FILE *cmd_file;

            snprintf(cmd_path, sizeof(cmd_path), "/proc/%s/cmdline", entry->d_name);

            if ((cmd_file = fopen(cmd_path, "r")) != NULL) {
                char cmd_line[512];

                fread(cmd_line, 1, sizeof(cmd_line), cmd_file);
                fclose(cmd_file);

                if (strstr(cmd_line, "gdb") || strstr(cmd_line, "ida") || strstr(cmd_line, "ghidra")) {
                    printf("Error: Debugger detected.\n");
                    closedir(proc_dir);
                    exit(0);
                }
            }
        }
    }
    closedir(proc_dir);

    char data[] = "RANDOM2";
    char flaghead[] = "running_proc";
    char flag[100];

    size_t data_len = strlen((const char *)data);

    char *rand = rc4(flaghead, data, data_len); 
    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

    printf("Enter second flag: ");
    scanf("%s", user_input);

    // Compare user input with the generated flag
    if (strcmp(user_input, flag) == 0) {
        printf("Second flag correct\n"); // Output when input matches the flag
    } else {
        printf("Incorrect. Try another flag\n"); // Prompt user to try again
    }
}

void task3(){
    FILE *file = fopen("/proc/self/status", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char tag[64], value[64];
        if (sscanf(line, "%63s %63s", tag, value) != 2)
            continue;

        if (strcmp(tag, "TracerPid:") == 0 && strcmp(value, "0") != 0) {
            fclose(file);
            exit(0);
        }
    }

    fclose(file);

    char data[] = "RANDOM3";
    char flaghead[] = "proc_status";
    char flag[100];

    size_t data_len = strlen((const char *)data);

    char *rand = rc4(flaghead, data, data_len); 
    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

    printf("Enter third flag: ");
    scanf("%s", user_input);

    // Compare user input with the generated flag
    if (strcmp(user_input, flag) == 0) {
        printf("Third flag correct\n"); // Output when input matches the flag
    } else {
        printf("Incorrect. Try another flag\n"); // Prompt user to try again
    }
}

void task4(){
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        printf("Error: Debugger detected.\n");
        exit(0);
    }

    char data[] = "RANDOM4";
    char flaghead[] = "self_tracing";
    char flag[100];

    size_t data_len = strlen((const char *)data);

    char *rand = rc4(flaghead, data, data_len); 
    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

    printf("Enter fourth flag: ");
    scanf("%s", user_input);

    // Compare user input with the generated flag
    if (strcmp(user_input, flag) == 0) {
        printf("Fourth flag correct\n"); // Output when input matches the flag
    } else {
        printf("Incorrect. Try another flag\n"); // Prompt user to try again
    }
}

void task5(){
    char data[] = "RANDOM5";
    char flaghead[] = "breakpoint_check";
    char flag[100];

    size_t data_len = strlen((const char *)data);

    char *rand = rc4(flaghead, data, data_len); 
    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

    printf("Enter fifth flag: ");
    scanf("%s", user_input);

    // Compare user input with the generated flag
    if (strcmp(user_input, flag) == 0) {
        printf("Fifth flag correct\n"); // Output when input matches the flag
    } else {
        printf("Incorrect. Try another flag\n"); // Prompt user to try again
    }
}

void task6(){
    pid_t parent_pid = getppid();

    char command[100];
    snprintf(command, sizeof(command), "ps -p %d -o comm=", parent_pid);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    char parent_process_name[100];
    if (fgets(parent_process_name, sizeof(parent_process_name), fp) != NULL) {
        printf("Parent Process Name: %s", parent_process_name);

        // Check for specific strings in the parent process name
        if (strstr(parent_process_name, "gdb") != NULL ||
            strstr(parent_process_name, "ida") != NULL ||
            strstr(parent_process_name, "ghidra") != NULL) {
            printf("Parent process name contains 'gdb', 'ida', or 'ghidra'.\n");
            exit(0);
        }
    } else {
        printf("Failed to retrieve parent process name.\n");
    }
    pclose(fp);

    char data[] = "RANDOM6";
    char flaghead[] = "parent_proc";
    char flag[100];

    size_t data_len = strlen((const char *)data);

    char *rand = rc4(flaghead, data, data_len); 
    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

    printf("Enter sixth flag: ");
    scanf("%s", user_input);

    // Compare user input with the generated flag
    if (strcmp(user_input, flag) == 0) {
        printf("Sixth flag correct\n"); // Output when input matches the flag
    } else {
        printf("Incorrect. Try another flag\n"); // Prompt user to try again
    }
}

void task7(){
    time_t start, end;
    double elapsed;

    time(&start); // Get the starting time
    char data[] = "RANDOM7";
    char flaghead[] = "time_exec";
    char flag[100];

    size_t data_len = strlen((const char *)data);

    char *rand = rc4(flaghead, data, data_len); 
    generateFlag(flag, flaghead, rand);

    char user_input[100];
    int correct = 0;

    time(&end); // Get the ending time

    elapsed = difftime(end, start); // Calculate the elapsed time

    if (elapsed > 1.0) {
        printf("Debugged\n");
        exit(0);
    }

    printf("Enter seventh flag: ");
    scanf("%s", user_input);

    // Compare user input with the generated flag
    if (strcmp(user_input, flag) == 0) {
        printf("Seventh flag correct\n"); // Output when input matches the flag
    } else {
        printf("Incorrect.\n"); // Prompt user to try again
    }
}

void swap(unsigned char *s, int i, int j) {
    unsigned char temp = s[i];
    s[i] = s[j];
    s[j] = temp;
}

char *rc4(unsigned char *key, unsigned char *data, size_t data_len) {
    unsigned char S[256];
    unsigned char T[256];
    size_t key_len = strlen((const char *)key);
    
    for (int i = 0; i < 256; i++) {
        S[i] = i;
        T[i] = key[i % key_len] ^ i; 
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        swap(S, i, j);
    }

    unsigned char *encrypted = (unsigned char *)malloc(data_len * sizeof(unsigned char));
    if (encrypted == NULL) {
        return NULL;
    }

    int i = 0, k = 0;
    for (size_t idx = 0; idx < data_len; idx++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S, i, j);
        int rand = S[(S[i] + S[j]) % 246];
        encrypted[k++] = data[idx] ^ rand;
    }

    char *hex_string = (char *)malloc((data_len * 2 + 1) * sizeof(char));
    if (hex_string == NULL) {
        free(encrypted);
        return NULL;
    }

    const char *hex_chars = "0123456789ABCDEF";

    for (size_t i = 0; i < data_len; i++) {
        hex_string[i * 2] = hex_chars[(encrypted[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_chars[encrypted[i] & 0xF];
    }

    hex_string[data_len * 2] = '\0';
    free(encrypted);
    return hex_string;
}
