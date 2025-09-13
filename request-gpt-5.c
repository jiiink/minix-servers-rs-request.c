/*
 * Changes:
 *   Jan 22, 2010:  Created  (Cristiano Giuffrida)
 */

#include "inc.h"

#include "kernel/proc.h"

static int check_request(struct rs_start *rs_start);

/*===========================================================================*
 *				   do_up				     *
 *===========================================================================*/
int do_up(m_ptr)
message *m_ptr;					/* request message pointer */
{
/* A request was made to start a new system service. */
  struct rproc *rp;
  struct rprocpub *rpub;
  int i, r;
  struct rs_start rs_start;
  int noblock;
  int init_flags = 0;

  /* Check if the call can be allowed. */
  if((r = check_call_permission(m_ptr->m_source, RS_UP, NULL)) != OK)
      return r;

  /* Allocate a new system service slot. */
  r = alloc_slot(&rp);
  if(r != OK) {
      printf("RS: do_up: unable to allocate a new slot: %d\n", r);
      return r;
  }
  rpub = rp->r_pub;

  /* Copy the request structure. */
  r = copy_rs_start(m_ptr->m_source, m_ptr->m_rs_req.addr, &rs_start);
  if (r != OK) {
      return r;
  }
  r = check_request(&rs_start);
  if (r != OK) {
      return r;
  }

  /* Check flags. */
  noblock = (rs_start.rss_flags & RSS_NOBLOCK);
  if(rs_start.rss_flags & RSS_FORCE_INIT_CRASH) {
      init_flags |= SEF_INIT_CRASH;
  }
  if(rs_start.rss_flags & RSS_FORCE_INIT_FAIL) {
      init_flags |= SEF_INIT_FAIL;
  }
  if(rs_start.rss_flags & RSS_FORCE_INIT_TIMEOUT) {
      init_flags |= SEF_INIT_TIMEOUT;
  }
  if(rs_start.rss_flags & RSS_FORCE_INIT_DEFCB) {
      init_flags |= SEF_INIT_DEFCB;
  }

  /* Initialize the slot as requested. */
  r = init_slot(rp, &rs_start, m_ptr->m_source);
  if(r != OK) {
      printf("RS: do_up: unable to init the new slot: %d\n", r);
      return r;
  }

  /* Check for duplicates */
  if(lookup_slot_by_label(rpub->label)) {
      printf("RS: service with the same label '%s' already exists\n",
          rpub->label);
      return EBUSY;
  }
  if(rpub->dev_nr>0 && lookup_slot_by_dev_nr(rpub->dev_nr)) {
      printf("RS: service with the same device number %d already exists\n",
          rpub->dev_nr);
      return EBUSY;
  }
  for (i = 0; i < rpub->nr_domain; i++) {
      if (lookup_slot_by_domain(rpub->domain[i]) != NULL) {
	  printf("RS: service with the same domain %d already exists\n",
	      rpub->domain[i]);
	  return EBUSY;
      }
  }

  /* All information was gathered. Now try to start the system service. */
  r = start_service(rp, init_flags);
  if(r != OK) {
      return r;
  }

  /* Unblock the caller immediately if requested. */
  if(noblock) {
      return OK;
  }

  /* Late reply - send a reply when service completes initialization. */
  rp->r_flags |= RS_LATEREPLY;
  rp->r_caller = m_ptr->m_source;
  rp->r_caller_request = RS_UP;

  return EDONTREPLY;
}

/*===========================================================================*
 *				do_down					     *
 *===========================================================================*/
int do_down(message *m_ptr)
{
    struct rproc *rp;
    int s;
    char label[RS_MAX_LABEL_LEN] = {0};
    int caller;

    if (m_ptr == NULL) {
        return EINVAL;
    }

    caller = m_ptr->m_source;

    s = copy_label(caller, m_ptr->m_rs_req.addr, m_ptr->m_rs_req.len, label, sizeof(label));
    if (s != OK) {
        return s;
    }
    label[sizeof(label) - 1] = '\0';

    rp = lookup_slot_by_label(label);
    if (rp == NULL) {
        if (rs_verbose) {
            printf("RS: do_down: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    s = check_call_permission(caller, RS_DOWN, rp);
    if (s != OK) {
        return s;
    }

    if (rp->r_flags & RS_TERMINATED) {
        if (rs_verbose) {
            printf("RS: recovery script performs service down...\n");
        }
        unpublish_service(rp);
        cleanup_service(rp);
        return OK;
    }

    stop_service(rp, RS_EXITING);

    rp->r_flags |= RS_LATEREPLY;
    rp->r_caller = caller;
    rp->r_caller_request = RS_DOWN;

    return EDONTREPLY;
}

/*===========================================================================*
 *				do_restart				     *
 *===========================================================================*/
int do_restart(message *m_ptr)
{
  struct rproc *rp;
  int result;
  char label[RS_MAX_LABEL_LEN];
  char script[MAX_SCRIPT_LEN];

  result = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if (result != OK) {
      return result;
  }

  rp = lookup_slot_by_label(label);
  if (rp == NULL) {
      if (rs_verbose) {
          printf("RS: do_restart: service '%s' not found\n", label);
      }
      return ESRCH;
  }

  result = check_call_permission(m_ptr->m_source, RS_RESTART, rp);
  if (result != OK) {
      return result;
  }

  if ((rp->r_flags & RS_TERMINATED) == 0) {
      if (rs_verbose) {
          printf("RS: %s is still running\n", srv_to_string(rp));
      }
      return EBUSY;
  }

  if (rs_verbose) {
      printf("RS: recovery script performs service restart...\n");
  }

  {
      size_t n;

      n = sizeof(script) - 1;
      strncpy(script, rp->r_script, n);
      script[n] = '\0';

      rp->r_script[0] = '\0';
      restart_service(rp);

      n = sizeof(rp->r_script) - 1;
      strncpy(rp->r_script, script, n);
      rp->r_script[n] = '\0';
  }

  return OK;
}

/*===========================================================================*
 *				do_clone				     *
 *===========================================================================*/
int do_clone(message *m_ptr)
{
    int result;
    char label[RS_MAX_LABEL_LEN] = {0};
    struct rproc *rp;
    struct rprocpub *rpub;

    if (m_ptr == NULL) {
        return EINVAL;
    }

    result = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
                        m_ptr->m_rs_req.len, label, sizeof(label));
    if (result != OK) {
        return result;
    }

    rp = lookup_slot_by_label(label);
    if (rp == NULL) {
        if (rs_verbose) {
            printf("RS: do_clone: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    rpub = rp->r_pub;
    if (rpub == NULL) {
        return EINVAL;
    }

    result = check_call_permission(m_ptr->m_source, RS_CLONE, rp);
    if (result != OK) {
        return result;
    }

    if (rp->r_next_rp != NULL) {
        return EEXIST;
    }

    rpub->sys_flags |= SF_USE_REPL;
    result = clone_service(rp, RST_SYS_PROC, 0);
    if (result != OK) {
        rpub->sys_flags &= ~SF_USE_REPL;
        return result;
    }

    return OK;
}

/*===========================================================================*
 *				do_unclone				     *
 *===========================================================================*/
int do_unclone(message *m_ptr)
{
    struct rproc *rp;
    struct rprocpub *rpub;
    int r;
    char label[RS_MAX_LABEL_LEN];

    label[0] = '\0';

    r = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
                   m_ptr->m_rs_req.len, label, sizeof(label));
    if (r != OK) {
        return r;
    }
    label[sizeof(label) - 1] = '\0';

    rp = lookup_slot_by_label(label);
    if (!rp) {
        if (rs_verbose) {
            printf("RS: do_unclone: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    r = check_call_permission(m_ptr->m_source, RS_UNCLONE, rp);
    if (r != OK) {
        return r;
    }

    rpub = rp->r_pub;
    if (!rpub) {
        return ESRCH;
    }

    if ((rpub->sys_flags & SF_USE_REPL) == 0) {
        return ENOENT;
    }

    rpub->sys_flags &= ~SF_USE_REPL;

    if (rp->r_next_rp != NULL) {
        cleanup_service_now(rp->r_next_rp);
        rp->r_next_rp = NULL;
    }

    return OK;
}

/*===========================================================================*
 *				    do_edit				     *
 *===========================================================================*/
int do_edit(message *m_ptr)
{
  struct rproc *rp;
  struct rprocpub *rpub;
  struct rs_start rs_start;
  int r;
  char label[RS_MAX_LABEL_LEN];
  int endpoint;
  int is_sys_proc;

  if (!m_ptr) {
      return EINVAL;
  }

  r = copy_rs_start(m_ptr->m_source, m_ptr->m_rs_req.addr, &rs_start);
  if (r != OK) {
      return r;
  }

  r = copy_label(m_ptr->m_source, rs_start.rss_label.l_addr,
      rs_start.rss_label.l_len, label, sizeof(label));
  if (r != OK) {
      return r;
  }

  rp = lookup_slot_by_label(label);
  if (!rp) {
      if (rs_verbose) {
          printf("RS: do_edit: service '%s' not found\n", label);
      }
      return ESRCH;
  }

  rpub = rp->r_pub;
  if (!rpub) {
      printf("RS: do_edit: missing public data for service '%s'\n", label);
      return EINVAL;
  }

  r = check_call_permission(m_ptr->m_source, RS_EDIT, rp);
  if (r != OK) {
      return r;
  }

  if (rs_verbose) {
      printf("RS: %s edits settings\n", srv_to_string(rp));
  }

  endpoint = rpub->endpoint;

  r = sys_getpriv(&rp->r_priv, endpoint);
  if (r != OK) {
      printf("RS: do_edit: unable to synch privilege structure: %d\n", r);
      return r;
  }

  r = sched_stop(rp->r_scheduler, endpoint);
  if (r != OK) {
      printf("RS: do_edit: scheduler won't give up process: %d\n", r);
      return r;
  }

  r = edit_slot(rp, &rs_start, m_ptr->m_source);
  if (r != OK) {
      printf("RS: do_edit: unable to edit the existing slot: %d\n", r);
      return r;
  }

  r = sys_privctl(endpoint, SYS_PRIV_UPDATE_SYS, &rp->r_priv);
  if (r != OK) {
      printf("RS: do_edit: unable to update privilege structure: %d\n", r);
      return r;
  }

  is_sys_proc = (rp->r_priv.s_flags & SYS_PROC) ? 1 : 0;
  r = vm_set_priv(endpoint, &rpub->vm_call_mask[0], is_sys_proc);
  if (r != OK) {
      printf("RS: do_edit: failed: %d\n", r);
      return r;
  }

  r = sched_init_proc(rp);
  if (r != OK) {
      printf("RS: do_edit: unable to reinitialize scheduling: %d\n", r);
      return r;
  }

  if (rpub->sys_flags & SF_USE_REPL) {
      if (rp->r_next_rp) {
          cleanup_service(rp->r_next_rp);
          rp->r_next_rp = NULL;
      }
      r = clone_service(rp, RST_SYS_PROC, 0);
      if (r != OK) {
          printf("RS: warning: unable to clone %s\n", srv_to_string(rp));
      }
  }

  return OK;
}

/*===========================================================================*
 *				do_refresh				     *
 *===========================================================================*/
int do_refresh(message *m_ptr)
{
    if (m_ptr == NULL) {
        return EINVAL;
    }

    char label[RS_MAX_LABEL_LEN] = {0};

    int s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
                       m_ptr->m_rs_req.len, label, sizeof(label));
    if (s != OK) {
        return s;
    }

    struct rproc *rp = lookup_slot_by_label(label);
    if (rp == NULL) {
        if (rs_verbose) {
            printf("RS: do_refresh: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    s = check_call_permission(m_ptr->m_source, RS_REFRESH, rp);
    if (s != OK) {
        return s;
    }

    if (rs_verbose) {
        printf("RS: %s refreshing\n", srv_to_string(rp));
    }
    stop_service(rp, RS_REFRESHING);

    rp->r_flags |= RS_LATEREPLY;
    rp->r_caller = m_ptr->m_source;
    rp->r_caller_request = RS_REFRESH;

    return EDONTREPLY;
}

/*===========================================================================*
 *				do_shutdown				     *
 *===========================================================================*/
int do_shutdown(message *m_ptr)
{
    if (m_ptr != NULL) {
        int perm = check_call_permission(m_ptr->m_source, RS_SHUTDOWN, NULL);
        if (perm != OK) {
            return perm;
        }
    }

    if (rs_verbose) {
        printf("RS: shutting down...\n");
    }

    shutting_down = TRUE;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) != 0) {
            rp->r_flags |= RS_EXITING;
        }
    }

    return OK;
}

/*===========================================================================*
 *				do_init_ready				     *
 *===========================================================================*/
int do_init_ready(message *m_ptr)
{
  struct rproc *rp;
  struct rprocpub *rpub;
  int who_p;
  int result;

  if (m_ptr == NULL) {
    return EINVAL;
  }

  who_p = _ENDPOINT_P(m_ptr->m_source);
  result = m_ptr->m_rs_init.result;

  rp = rproc_ptr[who_p];
  if (rp == NULL) {
    if (rs_verbose)
      printf("RS: do_init_ready: unknown source %d\n", m_ptr->m_source);
    return EINVAL;
  }

  rpub = rp->r_pub;
  if (rpub == NULL) {
    if (rs_verbose)
      printf("RS: do_init_ready: missing public data for %s\n", srv_to_string(rp));
    return EINVAL;
  }

  if (!(rp->r_flags & RS_INITIALIZING)) {
    if (rs_verbose)
      printf("RS: do_init_ready: got unexpected init ready msg from %d\n", m_ptr->m_source);
    return EINVAL;
  }

  if (result != OK) {
    if (rs_verbose)
      printf("RS: %s initialization error: %s\n", srv_to_string(rp), init_strerror(result));
    if (result == ERESTART && !SRV_IS_UPDATING(rp))
      rp->r_flags |= RS_REINCARNATE;
    crash_service(rp);
    rp->r_init_err = result;
    return EDONTREPLY;
  }

  if (rs_verbose)
    printf("RS: %s initialized\n", srv_to_string(rp));

  if (SRV_IS_UPDATING(rp)) {
    if (rupdate.num_init_ready_pending > 0) {
      rupdate.num_init_ready_pending--;
    } else if (rs_verbose) {
      printf("RS: do_init_ready: no pending inits but got ready from %s\n", srv_to_string(rp));
    }
    rp->r_flags |= RS_INIT_DONE;
    if (rupdate.num_init_ready_pending == 0) {
      printf("RS: update succeeded\n");
      end_update(OK, RS_REPLY);
    }
  } else {
    int r;
    message m = (message){0};
    m.m_type = OK;

    rp->r_flags &= ~RS_INITIALIZING;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();

    r = reply(rpub->endpoint, rp, &m);
    if (r != OK && rs_verbose) {
      printf("RS: do_init_ready: reply to %s failed: %d\n", srv_to_string(rp), r);
    }

    end_srv_init(rp);
  }

  return EDONTREPLY;
}

/*===========================================================================*
 *				do_update				     *
 *===========================================================================*/
int do_update(message *m_ptr)
{
  struct rproc *rp;
  struct rproc *trg_rp;
  struct rproc *new_rp;
  struct rprocpub *rpub;
  struct rprocupd *rpupd;
  struct rs_start rs_start;
  int s;
  char label[RS_MAX_LABEL_LEN];
  int noblock, do_self_update, force_self_update, batch_mode, prepare_only;
  int prepare_state, prepare_maxtime;
  endpoint_t state_endpoint;
  int lu_flags = 0;
  int init_flags = 0;
  int flags;

  s = copy_rs_start(m_ptr->m_source, m_ptr->m_rs_req.addr, &rs_start);
  if (s != OK) return s;

  s = copy_label(m_ptr->m_source, rs_start.rss_label.l_addr,
      rs_start.rss_label.l_len, label, sizeof(label));
  if (s != OK) return s;

  rp = lookup_slot_by_label(label);
  if (!rp) {
      if (rs_verbose) printf("RS: do_update: service '%s' not found\n", label);
      return ESRCH;
  }
  rpub = rp->r_pub;

  flags = rs_start.rss_flags;
  noblock = (flags & RSS_NOBLOCK);
  do_self_update = (flags & RSS_SELF_LU);
  force_self_update = (flags & RSS_FORCE_SELF_LU);
  batch_mode = (flags & RSS_BATCH);
  prepare_only = (flags & RSS_PREPARE_ONLY_LU);

  if ((flags & (RSS_SELF_LU | RSS_FORCE_SELF_LU)) != 0) lu_flags |= SEF_LU_SELF;
  if (prepare_only) lu_flags |= SEF_LU_PREPARE_ONLY;
  if (flags & RSS_ASR_LU) lu_flags |= SEF_LU_ASR;
  if (!prepare_only && (flags & RSS_DETACH)) lu_flags |= SEF_LU_DETACHED;

  if (rs_start.rss_map_prealloc_bytes <= 0 &&
      rpub->endpoint == VM_PROC_NR &&
      ((((lu_flags & (SEF_LU_SELF | SEF_LU_ASR)) != SEF_LU_SELF) ||
        (flags & RSS_FORCE_INIT_ST)) &&
       RS_VM_DEFAULT_MAP_PREALLOC_LEN > 0)) {
      rs_start.rss_map_prealloc_bytes = RS_VM_DEFAULT_MAP_PREALLOC_LEN;
      if (rs_verbose)
          printf("RS: %s gets %ld default mmap bytes\n", srv_to_string(rp),
                 rs_start.rss_map_prealloc_bytes);
  }
  if ((flags & RSS_NOMMAP_LU) || rs_start.rss_map_prealloc_bytes)
      lu_flags |= SEF_LU_NOMMAP;

  if (flags & RSS_FORCE_INIT_CRASH) init_flags |= SEF_INIT_CRASH;
  if (flags & RSS_FORCE_INIT_FAIL) init_flags |= SEF_INIT_FAIL;
  if (flags & RSS_FORCE_INIT_TIMEOUT) init_flags |= SEF_INIT_TIMEOUT;
  if (flags & RSS_FORCE_INIT_DEFCB) init_flags |= SEF_INIT_DEFCB;
  if (flags & RSS_FORCE_INIT_ST) init_flags |= SEF_INIT_ST;
  init_flags |= lu_flags;

  trg_rp = NULL;
  state_endpoint = NONE;
  if (rs_start.rss_trg_label.l_len > 0) {
      s = copy_label(m_ptr->m_source, rs_start.rss_trg_label.l_addr,
          rs_start.rss_trg_label.l_len, label, sizeof(label));
      if (s != OK) return s;

      trg_rp = lookup_slot_by_label(label);
      if (!trg_rp) {
          if (rs_verbose)
              printf("RS: do_update: target service '%s' not found\n", label);
          return ESRCH;
      }
      state_endpoint = trg_rp->r_pub->endpoint;
  }

  s = check_call_permission(m_ptr->m_source, RS_UPDATE, rp);
  if (s != OK) return s;

  prepare_state = m_ptr->m_rs_update.state;
  if (prepare_state == SEF_LU_STATE_NULL) return EINVAL;

  prepare_maxtime = m_ptr->m_rs_update.prepare_maxtime;
  if (prepare_maxtime == 0) prepare_maxtime = RS_DEFAULT_PREPARE_MAXTIME;

  if (RUPDATE_IS_UPDATING()) {
      printf("RS: an update is already in progress\n");
      return EBUSY;
  }

  if (RUPDATE_IS_UPD_SCHEDULED()) {
      if (!batch_mode) {
          printf("RS: an update is already scheduled, cannot start a new one\n");
          return EBUSY;
      }
      if (SRV_IS_UPD_SCHEDULED(rp)) {
          printf("RS: the specified process is already part of the currently scheduled update\n");
          return EINVAL;
      }
  }

  if (prepare_only &&
      (rp->r_pub->endpoint == VM_PROC_NR ||
       rp->r_pub->endpoint == PM_PROC_NR ||
       rp->r_pub->endpoint == VFS_PROC_NR)) {
      if (prepare_state != SEF_LU_STATE_UNREACHABLE) {
          printf("RS: prepare-only update for VM, PM and VFS is only supported with state %d\n",
                 SEF_LU_STATE_UNREACHABLE);
          return EINVAL;
      }
  }

  if (prepare_only && rp->r_pub->endpoint == RS_PROC_NR) {
      printf("RS: prepare-only update for RS is not supported\n");
      return EINVAL;
  }

  rpupd = &rp->r_upd;
  rupdate_upd_init(rpupd, rp);
  rpupd->lu_flags |= lu_flags;
  rpupd->init_flags |= init_flags;
  rupdate_set_new_upd_flags(rpupd);

  if (!prepare_only) {
      if (do_self_update) {
          if (rs_verbose)
              printf("RS: %s requested to perform self update\n", srv_to_string(rp));

          s = clone_service(rp, LU_SYS_PROC, rpupd->init_flags);
          if (s != OK) {
              printf("RS: do_update: unable to clone service: %d\n", s);
              return s;
          }
          new_rp = rp->r_new_rp;
      } else {
          if (rs_verbose)
              printf("RS: %s requested to perform %s update\n", srv_to_string(rp),
                     force_self_update ? "(forced) self" : "regular");

          s = alloc_slot(&new_rp);
          if (s != OK) {
              printf("RS: do_update: unable to allocate a new slot: %d\n", s);
              return s;
          }

          s = init_slot(new_rp, &rs_start, m_ptr->m_source);
          if (s != OK) {
              printf("RS: do_update: unable to init the new slot: %d\n", s);
              return s;
          }

          inherit_service_defaults(rp, new_rp);

          rp->r_new_rp = new_rp;
          new_rp->r_old_rp = rp;

          new_rp->r_priv.s_flags |= LU_SYS_PROC;
          new_rp->r_priv.s_init_flags |= rpupd->init_flags;

          s = create_service(new_rp);
          if (s != OK) {
              printf("RS: do_update: unable to create a new service: %d\n", s);
              return s;
          }
      }

      if (state_endpoint == NONE) state_endpoint = new_rp->r_pub->endpoint;

      if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
          s = update_sig_mgrs(new_rp, SELF, new_rp->r_pub->endpoint);
          if (s != OK) {
              cleanup_service(new_rp);
              return s;
          }
      }

      if (rs_start.rss_heap_prealloc_bytes < 0) rs_start.rss_heap_prealloc_bytes = 0;
      if (rs_start.rss_heap_prealloc_bytes) {
          size_t len = (size_t)rs_start.rss_heap_prealloc_bytes;
          if (rs_verbose)
              printf("RS: %s preallocating %ld heap bytes\n", srv_to_string(new_rp),
                     rs_start.rss_heap_prealloc_bytes);

          s = vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_HEAP_PREALLOC, NULL, &len);
          if (s != OK) {
              printf("vm_memctl(VM_RS_MEM_HEAP_PREALLOC) failed: %d\n", s);
              cleanup_service(new_rp);
              return s;
          }
          if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
              vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
          }
      }

      if (rs_start.rss_map_prealloc_bytes < 0) rs_start.rss_map_prealloc_bytes = 0;
      if (rs_start.rss_map_prealloc_bytes) {
          void *addr = NULL;
          if (rs_verbose)
              printf("RS: %s preallocating %ld mmap bytes\n", srv_to_string(new_rp),
                     rs_start.rss_map_prealloc_bytes);

          new_rp->r_map_prealloc_len = rs_start.rss_map_prealloc_bytes;
          s = vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_MAP_PREALLOC, &addr,
                        &new_rp->r_map_prealloc_len);
          if (s != OK) {
              printf("vm_memctl(VM_RS_MEM_MAP_PREALLOC) failed: %d\n", s);
              cleanup_service(new_rp);
              return s;
          }
          new_rp->r_map_prealloc_addr = (vir_bytes)addr;
      }
  }

  s = init_state_data(m_ptr->m_source, prepare_state, &rs_start.rss_state_data,
                      &rpupd->prepare_state_data);
  if (s != OK) {
      rupdate_upd_clear(rpupd);
      return s;
  }

  if (rpupd->prepare_state_data.size > 0) {
      struct rs_state_data *state_data = &rpupd->prepare_state_data;
      cp_grant_id_t gid;

      gid = cpf_grant_direct(rpub->endpoint, (vir_bytes)state_data, state_data->size, CPF_READ);
      if (gid == GRANT_INVALID) {
          rupdate_upd_clear(rpupd);
          return ENOMEM;
      }
      rpupd->prepare_state_data_gid = gid;

      state_data->ipcf_els_gid = GRANT_INVALID;
      if (state_data->ipcf_els) {
          gid = cpf_grant_direct(rpub->endpoint, (vir_bytes)state_data->ipcf_els,
                                 state_data->ipcf_els_size, CPF_READ);
          if (gid == GRANT_INVALID) {
              rupdate_upd_clear(rpupd);
              return ENOMEM;
          }
          state_data->ipcf_els_gid = (int)gid;
      }

      state_data->eval_gid = GRANT_INVALID;
      if (state_data->eval_addr) {
          gid = cpf_grant_direct(rpub->endpoint, (vir_bytes)state_data->eval_addr,
                                 state_data->eval_len, CPF_READ);
          if (gid == GRANT_INVALID) {
              rupdate_upd_clear(rpupd);
              return ENOMEM;
          }
          state_data->eval_gid = (int)gid;
      }
  }

  rpupd->prepare_state = prepare_state;
  rpupd->state_endpoint = state_endpoint;
  rpupd->prepare_tm = getticks();
  rpupd->prepare_maxtime = prepare_maxtime;
  rupdate_add_upd(rpupd);

  if (rs_verbose)
      printf("RS: %s scheduled for %s\n", srv_to_string(rp), srv_upd_to_string(rpupd));

  if (batch_mode) return OK;

  s = start_update_prepare(0);
  if (s == ESRCH) return OK;
  if (s != OK) return s;

  if (noblock) return OK;

  rupdate.last_rpupd->rp->r_flags |= RS_LATEREPLY;
  rupdate.last_rpupd->rp->r_caller = m_ptr->m_source;
  rupdate.last_rpupd->rp->r_caller_request = RS_UPDATE;

  return EDONTREPLY;
}

/*===========================================================================*
 *				do_upd_ready				     *
 *===========================================================================*/
int do_upd_ready(message *m_ptr)
{
  struct rproc *rp;
  struct rprocupd *rpupd;
  int who_p;
  int result;

  if (!m_ptr) return EINVAL;

  who_p = _ENDPOINT_P(m_ptr->m_source);
  rp = rproc_ptr[who_p];
  if (!rp) return EINVAL;

  result = m_ptr->m_rs_update.result;

  rpupd = rupdate.curr_rpupd;
  if (!rpupd || rp != rpupd->rp || RUPDATE_IS_INITIALIZING()) {
      if (rs_verbose)
          printf("RS: %s sent late/unexpected update ready msg\n",
              srv_to_string(rp));
      return EINVAL;
  }
  rp->r_flags |= RS_PREPARE_DONE;

  if (result != OK) {
      printf("RS: update failed: %s\n", lu_strerror(result));
      end_update(result, RS_REPLY);
      return EDONTREPLY;
  }

  if (rs_verbose)
      printf("RS: %s ready to update\n", srv_to_string(rp));

  if (start_update_prepare_next() == NULL) {
      start_update();
  }

  return EDONTREPLY;
}

/*===========================================================================*
 *				do_period				     *
 *===========================================================================*/
void do_period(m_ptr)
message *m_ptr;
{
  register struct rproc *rp;
  register struct rprocpub *rpub;
  clock_t now = m_ptr->m_notify.timestamp;
  int s;
  long period;

  /* If an update is in progress, check its status. */
  if(RUPDATE_IS_UPDATING() && !RUPDATE_IS_INITIALIZING()) {
      update_period(m_ptr);
  }

  /* Search system services table. Only check slots that are in use and not
   * updating.
   */
  for (rp=BEG_RPROC_ADDR; rp<END_RPROC_ADDR; rp++) {
      rpub = rp->r_pub;

      if ((rp->r_flags & RS_ACTIVE) && (!SRV_IS_UPDATING(rp) || ((rp->r_flags & (RS_INITIALIZING|RS_INIT_DONE|RS_INIT_PENDING)) == RS_INITIALIZING))) {

          /* Compute period. */
          period = rp->r_period;
          if(rp->r_flags & RS_INITIALIZING) {
              period = SRV_IS_UPDATING(rp) ? UPD_INIT_MAXTIME(&rp->r_upd) : RS_INIT_T;
          }

          /* If the service is to be revived (because it repeatedly exited, 
	   * and was not directly restarted), the binary backoff field is  
	   * greater than zero. 
	   */
	  if (rp->r_backoff > 0) {
              rp->r_backoff -= 1;
	      if (rp->r_backoff == 0) {
		  restart_service(rp);
	      }
	  }

	  /* If the service was signaled with a SIGTERM and fails to respond,
	   * kill the system service with a SIGKILL signal.
	   */
	  else if (rp->r_stop_tm > 0 && now - rp->r_stop_tm > 2*RS_DELTA_T
	   && rp->r_pid > 0) {
              rp->r_stop_tm = 0;
              crash_service(rp); /* simulate crash */
	  }

	  /* There seems to be no special conditions. If the service has a 
	   * period assigned check its status. 
	   */
	  else if (period > 0) {

	      /* Check if an answer to a status request is still pending. If 
	       * the service didn't respond within time, kill it to simulate 
	       * a crash. The failure will be detected and the service will 
	       * be restarted automatically. Give the service a free pass if
	       * somebody is initializing. There may be some weird dependencies
	       * if another service is, for example, restarting at the same
	       * time.
	       */
              if (rp->r_alive_tm < rp->r_check_tm) { 
	          if (now - rp->r_alive_tm > 2*period &&
		      rp->r_pid > 0 && !(rp->r_flags & RS_NOPINGREPLY)) {
		      struct rproc *rp2;
		      int init_flag;
		      if(rs_verbose)
                           printf("RS: %s reported late\n", srv_to_string(rp)); 
                      init_flag = rp->r_flags & RS_INITIALIZING;
                      rp->r_flags &= ~RS_INITIALIZING;
                      rp2 = lookup_slot_by_flags(RS_INITIALIZING);
                      rp->r_flags |= init_flag;
		      if(rp2 != NULL && !SRV_IS_UPDATING(rp)) {
                           /* Skip for now. */
                           if(rs_verbose)
                               printf("RS: %s gets a free pass\n",
                                   srv_to_string(rp)); 
                           rp->r_alive_tm = now;
                           rp->r_check_tm = now+1;
                           continue;
		      }
		      rp->r_flags |= RS_NOPINGREPLY;
                      crash_service(rp); /* simulate crash */
                      if(rp->r_flags & RS_INITIALIZING) {
                          rp->r_init_err = EINTR;
                      }
		  }
	      }

	      /* No answer pending. Check if a period expired since the last
	       * check and, if so request the system service's status.
	       */
	      else if (now - rp->r_check_tm > rp->r_period) {
  		  ipc_notify(rpub->endpoint);		/* request status */
		  rp->r_check_tm = now;			/* mark time */
              }
          }
      }
  }

  /* Reschedule a synchronous alarm for the next period. */
  if (OK != (s=sys_setalarm(RS_DELTA_T, 0)))
      panic("couldn't set alarm: %d", s);
}

/*===========================================================================*
 *			          do_sigchld				     *
 *===========================================================================*/
#include <errno.h>

void do_sigchld()
{
  pid_t pid;
  int status;

  if (rs_verbose) {
    printf("RS: got SIGCHLD signal, cleaning up dead children\n");
  }

  for (;;) {
    pid = waitpid(-1, &status, WNOHANG);
    if (pid > 0) {
      struct rproc *rp = lookup_slot_by_pid(pid);
      if (rp != NULL) {
        if (rs_verbose) {
          printf("RS: %s exited via another signal manager\n", srv_to_string(rp));
        }

        int found = 0;
        struct rproc **rps = NULL;
        int nr_rps = 0;
        int i = 0;

        get_service_instances(rp, &rps, &nr_rps);
        if (rps != NULL && nr_rps > 0) {
          for (i = 0; i < nr_rps; i++) {
            if (rps[i] == NULL) {
              continue;
            }
            if (SRV_IS_UPDATING(rps[i])) {
              rps[i]->r_flags &= ~(RS_UPDATING | RS_PREPARE_DONE | RS_INIT_DONE | RS_INIT_PENDING);
              found = 1;
            }
            free_slot(rps[i]);
          }
        }
        if (found) {
          rupdate_clear_upds();
        }
      }
    } else if (pid == 0) {
      break;
    } else {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
  }
}

/*===========================================================================*
 *				do_getsysinfo				     *
 *===========================================================================*/
int do_getsysinfo(m_ptr)
message *m_ptr;
{
  vir_bytes src_addr, dst_addr;
  int dst_proc;
  size_t size, len;
  int s;

  /* Check if the call can be allowed. */
  if((s = check_call_permission(m_ptr->m_source, 0, NULL)) != OK)
      return s;

  dst_proc = m_ptr->m_source;
  dst_addr = m_ptr->m_lsys_getsysinfo.where;
  size = m_ptr->m_lsys_getsysinfo.size;

  switch(m_ptr->m_lsys_getsysinfo.what) {
  case SI_PROC_TAB:
  	src_addr = (vir_bytes) rproc;
  	len = sizeof(struct rproc) * NR_SYS_PROCS;
  	break; 
  case SI_PROCALL_TAB:
	/* Copy out both tables, one after the other. */
	src_addr = (vir_bytes) rproc;
	len = sizeof(struct rproc) * NR_SYS_PROCS;
	if (len > size)
		return EINVAL;
	if ((s = sys_datacopy(SELF, src_addr, dst_proc, dst_addr, len)) != OK)
		return s;
	dst_addr += len;
	size -= len;
	/* FALLTHROUGH */
  case SI_PROCPUB_TAB:
  	src_addr = (vir_bytes) rprocpub;
  	len = sizeof(struct rprocpub) * NR_SYS_PROCS;
  	break; 
  default:
  	return(EINVAL);
  }

  if (len != size)
	return(EINVAL);

  return sys_datacopy(SELF, src_addr, dst_proc, dst_addr, len);
}

/*===========================================================================*
 *				do_lookup				     *
 *===========================================================================*/
int do_lookup(m_ptr)
message *m_ptr;
{
	static char namebuf[100];
	int len, r;
	struct rproc *rrp;
	struct rprocpub *rrpub;

	len = m_ptr->m_rs_req.name_len;

	if(len < 2 || len >= sizeof(namebuf)) {
		printf("RS: len too weird (%d)\n", len);
		return EINVAL;
	}

	if((r=sys_datacopy(m_ptr->m_source, (vir_bytes) m_ptr->m_rs_req.name,
		SELF, (vir_bytes) namebuf, len)) != OK) {
		printf("RS: name copy failed\n");
		return r;

	}

	namebuf[len] = '\0';

	rrp = lookup_slot_by_label(namebuf);
	if(!rrp) {
		return ESRCH;
	}
	rrpub = rrp->r_pub;
	m_ptr->m_rs_req.endpoint = rrpub->endpoint;

	return OK;
}

/*===========================================================================*
 *				do_sysctl				     *
 *===========================================================================*/
int do_sysctl(message *m_ptr)
{
	int r;
	int request_type;

	if (m_ptr == NULL) {
		return EINVAL;
	}

	request_type = m_ptr->m_rs_req.subtype;

	switch (request_type) {
		case RS_SYSCTL_SRV_STATUS:
			print_services_status();
			return OK;

		case RS_SYSCTL_UPD_START:
		case RS_SYSCTL_UPD_RUN: {
			const int allow_retries = 1;
			r = start_update_prepare(allow_retries);
			print_update_status();

			if (r != OK) {
				if (r == ESRCH) {
					return OK;
				}
				return r;
			}

			if (request_type == RS_SYSCTL_UPD_START) {
				return OK;
			}

			if (rupdate.last_rpupd == NULL || rupdate.last_rpupd->rp == NULL) {
				return EINVAL;
			}

			rupdate.last_rpupd->rp->r_flags |= RS_LATEREPLY;
			rupdate.last_rpupd->rp->r_caller = m_ptr->m_source;
			rupdate.last_rpupd->rp->r_caller_request = RS_UPDATE;
			return EDONTREPLY;
		}

		case RS_SYSCTL_UPD_STOP:
			r = abort_update_proc(EINTR);
			print_update_status();
			return r;

		case RS_SYSCTL_UPD_STATUS:
			print_update_status();
			return OK;

		default:
			printf("RS: bad sysctl type\n");
			return EINVAL;
	}
}

/*===========================================================================*
 *				do_fi				     *
 *===========================================================================*/
int do_fi(message *m_ptr)
{
  int status;
  struct rproc *rp;
  char label[RS_MAX_LABEL_LEN];

  if (m_ptr == NULL) {
    return EINVAL;
  }

  status = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if (status != OK) {
    return status;
  }

  rp = lookup_slot_by_label(label);
  if (rp == NULL) {
    if (rs_verbose) {
      printf("RS: do_fi: service '%s' not found\n", label);
    }
    return ESRCH;
  }

  status = check_call_permission(m_ptr->m_source, RS_FI, rp);
  if (status != OK) {
    return status;
  }

  return fi_service(rp);
}

/*===========================================================================*
 *				   check_request			     *
 *===========================================================================*/
static int check_request(struct rs_start *rs_start)
{
  if (rs_start == NULL) {
    printf("RS: check_request: null request pointer\n");
    return EINVAL;
  }

  /* Verify scheduling parameters */
  {
    int scheduler = rs_start->rss_scheduler;
    if (scheduler != KERNEL &&
        (scheduler < 0 || scheduler > LAST_SPECIAL_PROC_NR)) {
      printf("RS: check_request: invalid scheduler %d\n", scheduler);
      return EINVAL;
    }
  }

  {
    int priority = rs_start->rss_priority;
    if (priority >= NR_SCHED_QUEUES) {
      printf("RS: check_request: priority %u out of range\n",
             rs_start->rss_priority);
      return EINVAL;
    }
  }

  {
    int quantum = rs_start->rss_quantum;
    if (quantum <= 0) {
      printf("RS: check_request: quantum %u out of range\n",
             rs_start->rss_quantum);
      return EINVAL;
    }
  }

  {
    int cpu = rs_start->rss_cpu;
    if (cpu == RS_CPU_BSP) {
      rs_start->rss_cpu = machine.bsp_id;
    } else if (cpu == RS_CPU_DEFAULT) {
      /* keep the default value */
    } else if (cpu < 0) {
      return EINVAL;
    } else if (cpu > machine.processors_count) {
      printf("RS: cpu number %d out of range 0-%d, using BSP\n",
             cpu, machine.processors_count);
      rs_start->rss_cpu = machine.bsp_id;
    }
  }

  /* Verify signal manager. */
  {
    int sigmgr = rs_start->rss_sigmgr;
    if (sigmgr != SELF &&
        (sigmgr < 0 || sigmgr > LAST_SPECIAL_PROC_NR)) {
      printf("RS: check_request: invalid signal manager %d\n",
             sigmgr);
      return EINVAL;
    }
  }

  return OK;
}

