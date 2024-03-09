#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>

#define BUFFER_SIZE 1024

int calculate_md5(const char *file_path, unsigned char *digest) {
    FILE *file = fopen(file_path, "rb");
    if(!file) {
        perror("Calculating MD5. File error");
        return 1;
    }

    // MD5_Init
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);

    const EVP_MD *md = EVP_md5();
    EVP_DigestInit_ex(md_ctx, md, NULL);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) != 0) {
        // MD5_Update
        EVP_DigestUpdate(md_ctx, buffer, bytes_read);
    }

    // MD5_Final
    EVP_DigestFinal_ex(md_ctx, digest, NULL);
    EVP_MD_CTX_free(md_ctx);

    fclose(file);

    return 0;
}

void rename_file_to_md5(const char *file_path, const char *md5_str) {
    char dir_name[PATH_MAX];
    char base_name[PATH_MAX];
    
    snprintf(dir_name, PATH_MAX, "%s", dirname(strdup(file_path))); // get directory
    snprintf(base_name, PATH_MAX, "%s", basename(strdup(file_path))); // get filename

    if(strncmp(base_name, md5_str, 32) == 0) {
        // If already processed
        printf("%s\tis already processed\n", base_name);
    } else {
        char *file_extension = strrchr(base_name, '.');

        char new_path[PATH_MAX];
        snprintf(new_path, PATH_MAX, "%s/%s%s", dir_name, md5_str, file_extension);

        // Check if the file already exists
        struct stat st;
        int suffix = 0;
        while(stat(new_path, &st) == 0) { // Still no idea how this works
            snprintf(new_path, PATH_MAX, "%s/%s_%d%s", dir_name, md5_str, suffix++, file_extension);
        }

        if(rename(file_path, new_path) != 0) {
            perror("Error renaming file");
            fprintf(stderr, "Rename error. %s to %s\n", file_path, new_path);
            exit(EXIT_FAILURE);
        }
        printf("%s\t-> %s\n", base_name, md5_str);
    }
}

int check_extension(const char *file_path) {
    const char *ext[] = {".jpg", ".png", ".gif", ".webm", ".mp4", ".webp", ".jpeg", ".PNG", ".JPG", ".GIF", ".WEBM", ".MP4", ".WEBP", ".JPEG"};
    char *file_extension = strrchr(file_path, '.');

    if(file_extension && file_extension != file_path) {
        for (size_t i = 0; i < sizeof(ext) / sizeof(ext[0]); i++) {
            if (strcmp(file_extension, ext[i]) == 0) {
                return 1; // Supported extension
            }
        }
    }

    return 0; // Not a supported extension
}

void process(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if(!dir) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    struct stat file_info;
    int processed = 0; int excluded = 0; int pixiv = 0;

    while((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, PATH_MAX, "%s/%s", dir_path, entry->d_name);

        if(stat(full_path, &file_info) == 0) {
            if(S_ISDIR(file_info.st_mode)) {
                continue; // Skip directories
            } else if(S_ISREG(file_info.st_mode)) {
                if(strstr(entry->d_name,"_p0.") != NULL || strstr(entry->d_name, "_master1200") != NULL) {
                    // If pixiv filename
                    char pixiv_folder[PATH_MAX];
                    snprintf(pixiv_folder, PATH_MAX, "%s/pixiv", dir_path);

                    if(mkdir(pixiv_folder) != 0 && errno != EEXIST) {
                        perror("Error creating folder");
                        continue;
                    }

                    printf("->(Pixiv) Moving '%s'\n", entry->d_name);
                    char new_path[PATH_MAX];
                    snprintf(new_path, PATH_MAX, "%s/%s", pixiv_folder, entry->d_name);
                    if(rename(full_path, new_path) != 0) {
                        perror("Error moving file to pixiv folder");
                        fprintf(stderr, "Moving error, pixiv. %s to %s\n", full_path, new_path);
                        continue;
                    }
                    pixiv++;
                } else if(check_extension(full_path)) {
                    unsigned char digest[MD5_DIGEST_LENGTH];
                    if(calculate_md5(full_path, digest) == 0) {
                        char md5_str[2 * MD5_DIGEST_LENGTH + 1];
                        for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                            snprintf(md5_str + 2 * i, 3, "%02x", digest[i]);
                        }

                        rename_file_to_md5(full_path, md5_str);
                        processed++;
                    } else {
                        fprintf(stderr, "Error calculating MD5 for %s\n", full_path);
                    }
                } else {
                    // Not in extension list
                    char excluded_folder[PATH_MAX];
                    snprintf(excluded_folder, PATH_MAX, "%s/excluded", dir_path);

                    if(mkdir(excluded_folder) != 0 && errno != EEXIST) {
                        perror("Error creating folder");
                        continue;
                    }

                    printf("->(Excluded) Moving '%s'\n", entry->d_name);
                    char new_path[PATH_MAX];
                    snprintf(new_path, PATH_MAX, "%s/%s", excluded_folder, entry->d_name);
                    if(rename(full_path, new_path) != 0) {
                        perror("Error moving file to excluded folder");
                        fprintf(stderr, "Moving error, excluded. %s to %s\n", full_path, new_path);
                        continue;
                    }
                    excluded++;
                }
            }
        }
    }
    printf("\n\nProcessed:\t%d\nExcluded:\t%d\nPixiv:\t\t%d\n", processed, excluded, pixiv);
    closedir(dir);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Folder path: %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *folder_path = argv[1];
    process(folder_path);

    return EXIT_SUCCESS;
}