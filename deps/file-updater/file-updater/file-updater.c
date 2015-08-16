#include <util/threading.h>
#include <util/platform.h>
#include <util/darray.h>
#include <util/dstr.h>
#include <obs-data.h>
#include <curl/curl.h>
#include "file-updater.h"

#define warn(msg, ...) \
	blog(LOG_WARNING, "%s"msg, info->log_prefix, ##__VA_ARGS__)

struct update_info {
	char error[CURL_ERROR_SIZE];
	struct curl_slist *header;
	struct dstr file_data;
	CURL *curl;

	char *url;
	char *local;
	char *cache;
	char *log_prefix;
	char *user_agent;

	const char *remote_url;

	obs_data_t *local_package;
	obs_data_t *cache_package;
	obs_data_t *remote_package;

	pthread_t thread;
	bool thread_created;
};

void update_info_destroy(struct update_info *info)
{
	if (!info)
		return;

	if (info->thread_created)
		pthread_join(info->thread, NULL);

	dstr_free(&info->file_data);
	bfree(info->log_prefix);
	bfree(info->user_agent);
	bfree(info->cache);
	bfree(info->local);
	bfree(info->url);

	if (info->header)
		curl_slist_free_all(info->header);
	if (info->curl)
		curl_easy_cleanup(info->curl);
	if (info->local_package)
		obs_data_release(info->local_package);
	if (info->cache_package)
		obs_data_release(info->cache_package);
	if (info->remote_package)
		obs_data_release(info->remote_package);
	bfree(info);
}

static size_t http_write(char *ptr, size_t size, size_t nmemb,
		struct update_info *info)
{
	size_t total = size * nmemb;
	if (total)
		dstr_ncat(&info->file_data, ptr, total);

	return total;
}

static bool do_http_request(struct update_info *info, const char *url)
{
	CURLcode code;

	dstr_resize(&info->file_data, 0);
	curl_easy_setopt(info->curl, CURLOPT_URL, url);
	curl_easy_setopt(info->curl, CURLOPT_HTTPHEADER, info->header);
	curl_easy_setopt(info->curl, CURLOPT_ERRORBUFFER, info->error);
	curl_easy_setopt(info->curl, CURLOPT_WRITEFUNCTION, http_write);
	curl_easy_setopt(info->curl, CURLOPT_WRITEDATA, info);
	curl_easy_setopt(info->curl, CURLOPT_FAILONERROR, true);

	code = curl_easy_perform(info->curl);
	if (code != CURLE_OK) {
		warn("Remote update of URL \"%s\" failed: %s", url,
				info->error);
		return false;
	}

	return true;
}

static char *get_path(const char *dir, const char *file)
{
	struct dstr str = {0};

	dstr_copy(&str, dir);

	if (str.array && dstr_end(&str) != '/' && dstr_end(&str) != '\\')
		dstr_cat_ch(&str, '/');

	dstr_cat(&str, file);
	return str.array;
}

static inline obs_data_t *get_package(const char *base_path, const char *file)
{
	char *full_path = get_path(base_path, file);
	obs_data_t *package = obs_data_create_from_json_file(full_path);
	bfree(full_path);
	return package;
}

static bool init_update(struct update_info *info)
{
	struct dstr user_agent = {0};

	info->curl = curl_easy_init();
	if (!info->curl) {
		warn("Could not initialize Curl");
		return false;
	}

	info->local_package = get_package(info->local, "package.json");
	info->cache_package = get_package(info->cache, "package.json");

	dstr_copy(&user_agent, "User-Agent: ");
	dstr_cat(&user_agent, info->user_agent);

	info->header = curl_slist_append(info->header, user_agent.array);

	dstr_free(&user_agent);
	return true;
}

static void copy_local_to_cache(struct update_info *info, const char *file)
{
	char *local_file_path = get_path(info->local, file);
	char *cache_file_path = get_path(info->cache, file);

	os_copyfile(local_file_path, cache_file_path);

	bfree(local_file_path);
	bfree(cache_file_path);
}

static void enum_files(obs_data_t *package,
		bool (*enum_func)(void *param, obs_data_t *file),
		void *param)
{
	obs_data_array_t *array = obs_data_get_array(package, "files");
	size_t num;

	if (!array)
		return;

	num = obs_data_array_count(array);

	for (size_t i = 0; i < num; i++) {
		obs_data_t *file = obs_data_array_item(array, i);
		bool continue_enum = enum_func(param, file);
		obs_data_release(file);

		if (!continue_enum)
			break;
	}

	obs_data_array_release(array);
}

struct file_update_data {
	const char *name;
	int version;
	bool newer;
	bool found;
};

static bool newer_than_cache(void *param, obs_data_t *cache_file)
{
	struct file_update_data *input = param;
	const char *name = obs_data_get_string(cache_file, "name");
	int version = (int)obs_data_get_int(cache_file, "version");

	if (strcmp(input->name, name) == 0) {
		input->found = true;
		input->newer = input->version > version;
		return false;
	}

	return true;
}

static bool update_files_to_local(void *param, obs_data_t *local_file)
{
	struct update_info *info = param;
	struct file_update_data data = {
		.name = obs_data_get_string(local_file, "name"),
		.version = (int)obs_data_get_int(local_file, "version")
	};

	enum_files(info->cache_package, newer_than_cache, &data);
	if (data.newer || !data.found)
		copy_local_to_cache(info, data.name);

	return true;
}

static int update_local_version(struct update_info *info)
{
	int local_version;
	int cache_version = 0;

	local_version = (int)obs_data_get_int(info->local_package, "version");
	cache_version = (int)obs_data_get_int(info->cache_package, "version");

	/* if local cached version is out of date, copy new version */
	if (cache_version < local_version) {
		enum_files(info->local_package, update_files_to_local, info);
		copy_local_to_cache(info, "package.json");

		obs_data_release(info->cache_package);
		obs_data_addref(info->local_package);
		info->cache_package = info->local_package;

		return local_version;
	}

	return cache_version;
}

static inline bool do_relative_http_request(struct update_info *info,
		const char *url, const char *file)
{
	char *full_url = get_path(url, file);
	bool success = do_http_request(info, full_url);
	bfree(full_url);
	return success;
}

static inline void write_file_data(struct update_info *info,
		const char *base_path, const char *file)
{
	char *full_path = get_path(base_path, file);
	os_quick_write_utf8_file(full_path,
			info->file_data.array, info->file_data.len, false);
	bfree(full_path);
}

static bool update_remote_files(void *param, obs_data_t *remote_file)
{
	struct update_info *info = param;

	struct file_update_data data = {
		.name = obs_data_get_string(remote_file, "name"),
		.version = (int)obs_data_get_int(remote_file, "version")
	};

	enum_files(info->cache_package, newer_than_cache, &data);
	if (!data.newer && data.found)
		return true;

	if (!do_relative_http_request(info, info->remote_url, data.name))
		return true;

	write_file_data(info, info->cache, data.name);
	return true;
}

static bool update_remote_version(struct update_info *info, int cur_version)
{
	int remote_version;

	if (!info->file_data.array || info->file_data.array[0] != '{') {
		warn("Remote package does not exist or is not valid json");
		return false;
	}

	info->remote_package = obs_data_create_from_json(info->file_data.array);
	if (!info->remote_package) {
		warn("Failed to initialize remote package json");
		return false;
	}

	remote_version = obs_data_get_int(info->remote_package, "version");
	if (remote_version <= cur_version)
		return true;

	write_file_data(info, info->cache, "package.json");

	info->remote_url = obs_data_get_string(info->remote_package, "url");
	if (!info->remote_url) {
		warn("No remote url in package file");
		return false;
	}

	enum_files(info->remote_package, update_remote_files, info);
	return true;
}

static void *update_thread(void *data)
{
	struct update_info *info = data;
	int cur_version;

	if (!init_update(info))
		return NULL;

	cur_version = update_local_version(info);

	if (!do_http_request(info, info->url))
		return NULL;
	if (!update_remote_version(data, cur_version))
		return NULL;
	return NULL;
}

update_info_t *update_info_create(
		const char *log_prefix,
		const char *user_agent,
		const char *update_url,
		const char *local_dir,
		const char *cache_dir)
{
	struct update_info *info;

	if (!log_prefix)
		log_prefix = "";

	if (os_mkdir(cache_dir) < 0) {
		blog(LOG_WARNING, "%sCould not cache directory %s", log_prefix,
				cache_dir);
		return NULL;
	}

	info = bzalloc(sizeof(*info));
	info->log_prefix = bstrdup(log_prefix);
	info->user_agent = bstrdup(user_agent);
	info->local = bstrdup(local_dir);
	info->cache = bstrdup(cache_dir);
	info->url = get_path(update_url, "package.json");

	if (pthread_create(&info->thread, NULL, update_thread, info) == 0)
		info->thread_created = true;

	return info;
}
