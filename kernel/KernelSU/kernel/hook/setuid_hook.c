#ifdef CONFIG_KSU_SUSFS
extern struct work_struct susfs_extra_works;
#endif

static __always_inline void ksu_handle_setresuid_cred(struct cred *new, const struct cred *old)
{
	if (!new || !old)
		return;

	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);

	// old process is not root, ignore it.
	if (unlikely(!!old_uid))
		return;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS
	// We only care about processes spawned by zygote.
	if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
		goto no_susfs;

	// The manager uid is excluded from allow_list, and ksu_uid_should_umount()
	// returns true for it, so check the manager first.
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	// Isolated services spawned by zygote are always umounted.
	if (is_isolated_process(new_uid)) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		goto do_susfs_umount;
	}

	// Normal user app that should be umounted.
	if (likely(is_appuid(new_uid) && ksu_uid_should_umount(new_uid))) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		goto do_susfs_umount;
	}

	// Disable seccomp restriction for root allowed apps, running with
	// "su" disables seccomp anyway.
	if (ksu_is_allow_uid_for_current(new_uid)) {
		disable_seccomp();
		return;
	}

	// Process not umounted but also root not allowed.
	susfs_set_current_proc_no_su();
	return;

do_susfs_umount:
	ksu_handle_umount(new, old);
	if (!work_pending(&susfs_extra_works))
		schedule_work(&susfs_extra_works);
	return;

no_susfs:
#endif // #ifdef CONFIG_KSU_SUSFS

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	if (ksu_is_allow_uid_for_current(new_uid))
		goto kill_seccomp;

	// Handle kernel umount
	ksu_handle_umount(new, old);
	return;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	set_thread_flag(TIF_KSU_MANAGED); // sucompat fast-path
	return;
}
