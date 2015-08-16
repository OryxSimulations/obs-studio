#pragma once

struct update_info;
typedef struct update_info update_info_t;

update_info_t *update_info_create(
		const char *log_prefix,
		const char *user_agent,
		const char *update_url,
		const char *local_dir,
		const char *cache_dir);
void update_info_destroy(update_info_t *info);
