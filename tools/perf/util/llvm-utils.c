// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015, Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015, Huawei Inc.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/zalloc.h>
#include "debug.h"
#include "llvm-utils.h"
#include "config.h"
#include "util.h"
#include <sys/wait.h>
#include <api/strbuf.h>
#include <subcmd/exec-cmd.h>
#include <subcmd/run-command.h>

#define CLANG_BPF_CMD_DEFAULT_TEMPLATE				\
		"$CLANG_EXEC -D__KERNEL__ -D__NR_CPUS__=$NR_CPUS "\
		"-DLINUX_VERSION_CODE=$LINUX_VERSION_CODE "	\
		"$CLANG_OPTIONS $PERF_BPF_INC_OPTIONS $KERNEL_INC_OPTIONS " \
		"-Wno-unused-value -Wno-pointer-sign "		\
		"-working-directory $WORKING_DIR "		\
		"-c \"$CLANG_SOURCE\" -target bpf $CLANG_EMIT_LLVM -g -O2 -o - $LLVM_OPTIONS_PIPE"

struct llvm_param llvm_param = {
	.clang_path = "clang",
	.llc_path = "llc",
	.clang_bpf_cmd_template = CLANG_BPF_CMD_DEFAULT_TEMPLATE,
	.clang_opt = NULL,
	.opts = NULL,
	.kbuild_dir = NULL,
	.kbuild_opts = NULL,
	.user_set_param = false,
};

static void version_notice(void);

int perf_llvm_config(const char *var, const char *value)
{
	if (!strstarts(var, "llvm."))
		return 0;
	var += sizeof("llvm.") - 1;

	if (!strcmp(var, "clang-path"))
		llvm_param.clang_path = strdup(value);
	else if (!strcmp(var, "clang-bpf-cmd-template"))
		llvm_param.clang_bpf_cmd_template = strdup(value);
	else if (!strcmp(var, "clang-opt"))
		llvm_param.clang_opt = strdup(value);
	else if (!strcmp(var, "kbuild-dir"))
		llvm_param.kbuild_dir = strdup(value);
	else if (!strcmp(var, "kbuild-opts"))
		llvm_param.kbuild_opts = strdup(value);
	else if (!strcmp(var, "dump-obj"))
		llvm_param.dump_obj = !!perf_config_bool(var, value);
	else if (!strcmp(var, "opts"))
		llvm_param.opts = strdup(value);
	else {
		pr_debug("Invalid LLVM config option: %s\n", value);
		return -1;
	}
	llvm_param.user_set_param = true;
	return 0;
}

static int
search_program(const char *def, const char *name,
	       char *output)
{
	char *env, *path, *tmp = NULL;
	char buf[PATH_MAX];
	int ret;

	output[0] = '\0';
	if (def && def[0] != '\0') {
		if (def[0] == '/') {
			if (access(def, F_OK) == 0) {
				strlcpy(output, def, PATH_MAX);
				return 0;
			}
		} else if (def[0] != '\0')
			name = def;
	}

	env = getenv("PATH");
	if (!env)
		return -1;
	env = strdup(env);
	if (!env)
		return -1;

	ret = -ENOENT;
	path = strtok_r(env, ":",  &tmp);
	while (path) {
		scnprintf(buf, sizeof(buf), "%s/%s", path, name);
		if (access(buf, F_OK) == 0) {
			strlcpy(output, buf, PATH_MAX);
			ret = 0;
			break;
		}
		path = strtok_r(NULL, ":", &tmp);
	}

	free(env);
	return ret;
}

static int search_program_and_warn(const char *def, const char *name,
				   char *output)
{
	int ret = search_program(def, name, output);

	if (ret) {
		pr_err("ERROR:\tunable to find %s.\n"
		       "Hint:\tTry to install latest clang/llvm to support BPF. Check your $PATH\n"
		       "     \tand '%s-path' option in [llvm] section of ~/.perfconfig.\n",
		       name, name);
		version_notice();
	}
	return ret;
}

static inline void
force_set_env(const char *var, const char *value)
{
	if (value) {
		setenv(var, value, 1);
		pr_debug("set env: %s=%s\n", var, value);
	} else {
		unsetenv(var);
		pr_debug("unset env: %s\n", var);
	}
}

static void
version_notice(void)
{
	pr_err(
"     \tLLVM 3.7 or newer is required. Which can be found from http://llvm.org\n"
"     \tYou may want to try git trunk:\n"
"     \t\tgit clone http://llvm.org/git/llvm.git\n"
"     \t\t     and\n"
"     \t\tgit clone http://llvm.org/git/clang.git\n\n"
"     \tOr fetch the latest clang/llvm 3.7 from pre-built llvm packages for\n"
"     \tdebian/ubuntu:\n"
"     \t\thttps://apt.llvm.org/\n\n"
"     \tIf you are using old version of clang, change 'clang-bpf-cmd-template'\n"
"     \toption in [llvm] section of ~/.perfconfig to:\n\n"
"     \t  \"$CLANG_EXEC $CLANG_OPTIONS $KERNEL_INC_OPTIONS $PERF_BPF_INC_OPTIONS \\\n"
"     \t     -working-directory $WORKING_DIR -c $CLANG_SOURCE \\\n"
"     \t     -emit-llvm -o - | /path/to/llc -march=bpf -filetype=obj -o -\"\n"
"     \t(Replace /path/to/llc with path to your llc)\n\n"
);
}

static int detect_kbuild_dir(struct strbuf *kbuild_dir)
{
	const char *test_dir = llvm_param.kbuild_dir;
	const char *prefix_dir = "";
	const char *suffix_dir = "";

	/* _UTSNAME_LENGTH is 65 */
	char release[128];

	char *autoconf_path;

	int err;

	if (!test_dir) {
		err = fetch_kernel_version(NULL, release,
					   sizeof(release));
		if (err)
			return -EINVAL;

		test_dir = release;
		prefix_dir = "/lib/modules/";
		suffix_dir = "/build";
	}

	err = asprintf(&autoconf_path, "%s%s%s/include/generated/autoconf.h",
		       prefix_dir, test_dir, suffix_dir);
	if (err < 0)
		return -ENOMEM;

	if (access(autoconf_path, R_OK) == 0) {
		free(autoconf_path);

		err = (int)strbuf_addf(kbuild_dir, "%s%s%s", prefix_dir, test_dir, suffix_dir);
		if (err < 0)
			return err;
		return 0;
	}
	pr_debug("%s: Couldn't find \"%s\", missing kernel-devel package?.\n",
		 __func__, autoconf_path);
	free(autoconf_path);
	return -ENOENT;
}

static const char *kinc_fetch_script =
"#!/usr/bin/env sh\n"
"if ! test -d \"$KBUILD_DIR\"\n"
"then\n"
"	exit 1\n"
"fi\n"
"if ! test -f \"$KBUILD_DIR/include/generated/autoconf.h\"\n"
"then\n"
"	exit 1\n"
"fi\n"
"TMPDIR=`mktemp -d`\n"
"if test -z \"$TMPDIR\"\n"
"then\n"
"    exit 1\n"
"fi\n"
"cat << EOF > $TMPDIR/Makefile\n"
"obj-y := dummy.o\n"
"\\$(obj)/%.o: \\$(src)/%.c\n"
"\t@echo -n \"\\$(NOSTDINC_FLAGS) \\$(LINUXINCLUDE) \\$(EXTRA_CFLAGS)\"\n"
"\t\\$(CC) -c -o \\$@ \\$<\n"
"EOF\n"
"touch $TMPDIR/dummy.c\n"
"make -s -C $KBUILD_DIR M=$TMPDIR $KBUILD_OPTS dummy.o 2>/dev/null\n"
"RET=$?\n"
"rm -rf $TMPDIR\n"
"exit $RET\n";

void llvm__get_kbuild_opts(struct strbuf *kbuild_dir, struct strbuf *kbuild_include_opts)
{
	static char *saved_kbuild_dir;
	static char *saved_kbuild_include_opts;
	int err;

	if (!kbuild_dir || !kbuild_include_opts)
		return;

	if (saved_kbuild_dir && saved_kbuild_include_opts &&
	    !IS_ERR(saved_kbuild_dir) && !IS_ERR(saved_kbuild_include_opts)) {
		strbuf_addstr(kbuild_dir, saved_kbuild_dir);
		strbuf_addstr(kbuild_include_opts, saved_kbuild_include_opts);

		/*
		 * Don't fallthrough: it may break the saved_kbuild_dir and
		 * saved_kbuild_include_opts if they are detected again when
		 * memory is low.
		 */
		return;
	}

	if (llvm_param.kbuild_dir && !llvm_param.kbuild_dir[0]) {
		pr_debug("[llvm.kbuild-dir] is set to \"\" deliberately.\n");
		pr_debug("Skip kbuild options detection.\n");
		goto errout;
	}

	err = detect_kbuild_dir(kbuild_dir);
	if (err) {
		pr_warning(
"WARNING:\tunable to get correct kernel building directory.\n"
"Hint:\tSet correct kbuild directory using 'kbuild-dir' option in [llvm]\n"
"     \tsection of ~/.perfconfig or set it to \"\" to suppress kbuild\n"
"     \tdetection.\n\n");
		goto errout;
	}

	pr_debug("Kernel build dir is set to %s\n", kbuild_dir->buf);
	force_set_env("KBUILD_DIR", kbuild_dir->buf);
	force_set_env("KBUILD_OPTS", llvm_param.kbuild_opts);
	err = run_command_strbuf(kinc_fetch_script, kbuild_include_opts);
	if (err) {
		pr_warning(
"WARNING:\tunable to get kernel include directories from '%s'\n"
"Hint:\tTry set clang include options using 'clang-bpf-cmd-template'\n"
"     \toption in [llvm] section of ~/.perfconfig and set 'kbuild-dir'\n"
"     \toption in [llvm] to \"\" to suppress this detection.\n\n",
			kbuild_dir->buf);

		zfree(kbuild_dir);
		goto errout;
	}

	pr_debug("include option is set to %s\n", kbuild_include_opts->buf);

	saved_kbuild_dir = strdup(kbuild_dir->buf);
	saved_kbuild_include_opts = strdup(kbuild_include_opts->buf);

	if (!saved_kbuild_dir || !saved_kbuild_include_opts) {
		zfree(&saved_kbuild_dir);
		zfree(&saved_kbuild_include_opts);
	}
	return;
errout:
	saved_kbuild_dir = ERR_PTR(-EINVAL);
	saved_kbuild_include_opts = ERR_PTR(-EINVAL);
}

int llvm__get_nr_cpus(void)
{
	static int nr_cpus_avail = 0;
	char serr[STRERR_BUFSIZE];

	if (nr_cpus_avail > 0)
		return nr_cpus_avail;

	nr_cpus_avail = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_cpus_avail <= 0) {
		pr_err(
"WARNING:\tunable to get available CPUs in this system: %s\n"
"        \tUse 128 instead.\n", str_error_r(errno, serr, sizeof(serr)));
		nr_cpus_avail = 128;
	}
	return nr_cpus_avail;
}

void llvm__dump_obj(const char *path, void *obj_buf, size_t size)
{
	char *obj_path = strdup(path);
	FILE *fp;
	char *p;

	if (!obj_path) {
		pr_warning("WARNING: Not enough memory, skip object dumping\n");
		return;
	}

	p = strrchr(obj_path, '.');
	if (!p || (strcmp(p, ".c") != 0)) {
		pr_warning("WARNING: invalid llvm source path: '%s', skip object dumping\n",
			   obj_path);
		goto out;
	}

	p[1] = 'o';
	fp = fopen(obj_path, "wb");
	if (!fp) {
		pr_warning("WARNING: failed to open '%s': %s, skip object dumping\n",
			   obj_path, strerror(errno));
		goto out;
	}

	pr_debug("LLVM: dumping %s\n", obj_path);
	if (fwrite(obj_buf, size, 1, fp) != 1)
		pr_debug("WARNING: failed to write to file '%s': %s, skip object dumping\n", obj_path, strerror(errno));
	fclose(fp);
out:
	free(obj_path);
}

int llvm__compile_bpf(const char *path, struct strbuf *obj_buf)
{
	int err, nr_cpus_avail;
	unsigned int kernel_version;
	char linux_version_code_str[64];
	const char *clang_opt = llvm_param.clang_opt;
	char clang_path[PATH_MAX], llc_path[PATH_MAX], abspath[PATH_MAX], nr_cpus_avail_str[64];
	char serr[STRERR_BUFSIZE];
	char *perf_bpf_include_opts = NULL;
	const char *template = llvm_param.clang_bpf_cmd_template;
	char *pipe_template = NULL;
	const char *opts = llvm_param.opts;
	char *command_echo = NULL;
	char *libbpf_include_dir = system_path(LIBBPF_INCLUDE_DIR);
	struct strbuf kbuild_dir = STRBUF_INIT;
	struct strbuf kbuild_include_opts = STRBUF_INIT;
	struct strbuf command_out = STRBUF_INIT;

	if (path[0] != '-' && realpath(path, abspath) == NULL) {
		err = errno;
		pr_err("ERROR: problems with path %s: %s\n",
		       path, str_error_r(err, serr, sizeof(serr)));
		return -err;
	}

	if (!template)
		template = CLANG_BPF_CMD_DEFAULT_TEMPLATE;

	err = search_program_and_warn(llvm_param.clang_path,
			     "clang", clang_path);
	if (err)
		return -ENOENT;

	/*
	 * This is an optional work. Even it fail we can continue our
	 * work. Needn't check error return.
	 */
	llvm__get_kbuild_opts(&kbuild_dir, &kbuild_include_opts);

	nr_cpus_avail = llvm__get_nr_cpus();
	snprintf(nr_cpus_avail_str, sizeof(nr_cpus_avail_str), "%d",
		 nr_cpus_avail);

	if (fetch_kernel_version(&kernel_version, NULL, 0))
		kernel_version = 0;

	snprintf(linux_version_code_str, sizeof(linux_version_code_str),
		 "0x%x", kernel_version);
	if (asprintf(&perf_bpf_include_opts, "-I%s/", libbpf_include_dir) < 0)
		goto errout;
	force_set_env("NR_CPUS", nr_cpus_avail_str);
	force_set_env("LINUX_VERSION_CODE", linux_version_code_str);
	force_set_env("CLANG_EXEC", clang_path);
	force_set_env("CLANG_OPTIONS", clang_opt);
	force_set_env("KERNEL_INC_OPTIONS", kbuild_include_opts.buf);
	force_set_env("PERF_BPF_INC_OPTIONS", perf_bpf_include_opts);
	force_set_env("WORKING_DIR", kbuild_dir.len ? kbuild_dir.buf : ".");

	if (opts) {
		err = search_program_and_warn(llvm_param.llc_path, "llc", llc_path);
		if (err)
			goto errout;

		err = -ENOMEM;
		if (asprintf(&pipe_template, "%s -emit-llvm | %s -march=bpf %s -filetype=obj -o -",
			      template, llc_path, opts) < 0) {
			pr_err("ERROR:\tnot enough memory to setup command line\n");
			goto errout;
		}

		template = pipe_template;

	}

	/*
	 * Since we may reset clang's working dir, path of source file
	 * should be transferred into absolute path, except we want
	 * stdin to be source file (testing).
	 */
	force_set_env("CLANG_SOURCE",
		      (path[0] == '-') ? path : abspath);

	pr_debug("llvm compiling command template: %s\n", template);

	/*
	 * Below, substitute control characters for values that can cause the
	 * echo to misbehave, then substitute the values back.
	 */
	err = -ENOMEM;
	if (asprintf(&command_echo, "echo -n \a%s\a", template) < 0)
		goto errout;

#define SWAP_CHAR(a, b) do { if (*p == a) *p = b; } while (0)
	for (char *p = command_echo; *p; p++) {
		SWAP_CHAR('<', '\001');
		SWAP_CHAR('>', '\002');
		SWAP_CHAR('"', '\003');
		SWAP_CHAR('\'', '\004');
		SWAP_CHAR('|', '\005');
		SWAP_CHAR('&', '\006');
		SWAP_CHAR('\a', '"');
	}
	err = run_command_strbuf(command_echo, &command_out);
	if (err < 0)
		goto errout;

	for (char *p = command_out.buf; *p; p++) {
		SWAP_CHAR('\001', '<');
		SWAP_CHAR('\002', '>');
		SWAP_CHAR('\003', '"');
		SWAP_CHAR('\004', '\'');
		SWAP_CHAR('\005', '|');
		SWAP_CHAR('\006', '&');
	}
#undef SWAP_CHAR
	pr_debug("llvm compiling command : %s\n", command_out.buf);

	err = run_command_strbuf(template, obj_buf);
	if (err < 0) {
		pr_err("ERROR:\tunable to compile %s\n", path);
		pr_err("Hint:\tCheck error message shown above.\n");
		pr_err("Hint:\tYou can also pre-compile it into .o using:\n");
		pr_err("     \t\tclang -target bpf -O2 -c %s\n", path);
		pr_err("     \twith proper -I and -D options.\n");
		goto errout;
	}

	err = 0;
errout:
	free(command_echo);
	strbuf_release(&command_out);
	strbuf_release(&kbuild_dir);
	strbuf_release(&kbuild_include_opts);
	free(perf_bpf_include_opts);
	free(libbpf_include_dir);
	free(pipe_template);
	return err;
}

int llvm__search_clang(void)
{
	char clang_path[PATH_MAX];

	return search_program_and_warn(llvm_param.clang_path, "clang", clang_path);
}
