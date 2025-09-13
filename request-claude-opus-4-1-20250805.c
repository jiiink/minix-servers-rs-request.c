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
    char label[RS_MAX_LABEL_LEN];

    s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
        m_ptr->m_rs_req.len, label, sizeof(label));
    if(s != OK) {
        return s;
    }

    rp = lookup_slot_by_label(label);
    if(!rp) {
        if(rs_verbose) {
            printf("RS: do_down: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    s = check_call_permission(m_ptr->m_source, RS_DOWN, rp);
    if(s != OK) {
        return s;
    }

    if (rp->r_flags & RS_TERMINATED) {
        if(rs_verbose) {
            printf("RS: recovery script performs service down...\n");
        }
        unpublish_service(rp);
        cleanup_service(rp);
        return OK;
    }
    
    stop_service(rp, RS_EXITING);

    rp->r_flags |= RS_LATEREPLY;
    rp->r_caller = m_ptr->m_source;
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
    char script_backup[MAX_SCRIPT_LEN];

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

    if (strlcpy(script_backup, rp->r_script, sizeof(script_backup)) >= sizeof(script_backup)) {
        return ENAMETOOLONG;
    }

    rp->r_script[0] = '\0';
    restart_service(rp);

    if (strlcpy(rp->r_script, script_backup, MAX_SCRIPT_LEN) >= MAX_SCRIPT_LEN) {
        rp->r_script[0] = '\0';
        return ENAMETOOLONG;
    }

    return OK;
}

/*===========================================================================*
 *				do_clone				     *
 *===========================================================================*/
int do_clone(message *m_ptr)
{
    struct rproc *rp;
    struct rprocpub *rpub;
    int result;
    char label[RS_MAX_LABEL_LEN];

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
    char label[RS_MAX_LABEL_LEN];
    int result;

    if (!m_ptr) {
        return EINVAL;
    }

    result = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
                       m_ptr->m_rs_req.len, label, sizeof(label));
    if (result != OK) {
        return result;
    }

    rp = lookup_slot_by_label(label);
    if (!rp) {
        if (rs_verbose) {
            printf("RS: do_unclone: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    rpub = rp->r_pub;
    if (!rpub) {
        return EINVAL;
    }

    result = check_call_permission(m_ptr->m_source, RS_UNCLONE, rp);
    if (result != OK) {
        return result;
    }

    if (!(rpub->sys_flags & SF_USE_REPL)) {
        return ENOENT;
    }

    rpub->sys_flags &= ~SF_USE_REPL;
    
    if (rp->r_next_rp) {
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

    r = check_call_permission(m_ptr->m_source, RS_EDIT, rp);
    if (r != OK) {
        return r;
    }

    if (rs_verbose) {
        printf("RS: %s edits settings\n", srv_to_string(rp));
    }

    r = sys_getpriv(&rp->r_priv, rpub->endpoint);
    if (r != OK) {
        printf("RS: do_edit: unable to synch privilege structure: %d\n", r);
        return r;
    }

    r = sched_stop(rp->r_scheduler, rpub->endpoint);
    if (r != OK) {
        printf("RS: do_edit: scheduler won't give up process: %d\n", r);
        return r;
    }

    r = edit_slot(rp, &rs_start, m_ptr->m_source);
    if (r != OK) {
        printf("RS: do_edit: unable to edit the existing slot: %d\n", r);
        return r;
    }

    r = sys_privctl(rpub->endpoint, SYS_PRIV_UPDATE_SYS, &rp->r_priv);
    if (r != OK) {
        printf("RS: do_edit: unable to update privilege structure: %d\n", r);
        return r;
    }

    r = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0],
        !!(rp->r_priv.s_flags & SYS_PROC));
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
  struct rproc *rp;
  int s;
  char label[RS_MAX_LABEL_LEN];

  s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if(s != OK) {
      return s;
  }

  rp = lookup_slot_by_label(label);
  if(!rp) {
      if(rs_verbose) {
          printf("RS: do_refresh: service '%s' not found\n", label);
      }
      return ESRCH;
  }

  s = check_call_permission(m_ptr->m_source, RS_REFRESH, rp);
  if(s != OK) {
      return s;
  }

  if(rs_verbose) {
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
    int slot_nr;
    struct rproc *rp;
    int r;

    if (m_ptr != NULL) {
        r = check_call_permission(m_ptr->m_source, RS_SHUTDOWN, NULL);
        if (r != OK) {
            return r;
        }
    }

    if (rs_verbose) {
        printf("RS: shutting down...\n");
    }

    shutting_down = TRUE;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        if (rp->r_flags & RS_IN_USE) {
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
    int who_p;
    int result;
    struct rproc *rp;
    struct rprocpub *rpub;

    if (!m_ptr) {
        return EINVAL;
    }

    who_p = _ENDPOINT_P(m_ptr->m_source);
    result = m_ptr->m_rs_init.result;

    rp = rproc_ptr[who_p];
    if (!rp) {
        return EINVAL;
    }

    rpub = rp->r_pub;
    if (!rpub) {
        return EINVAL;
    }

    if (!(rp->r_flags & RS_INITIALIZING)) {
        if (rs_verbose) {
            printf("RS: do_init_ready: got unexpected init ready msg from %d\n",
                m_ptr->m_source);
        }
        return EINVAL;
    }

    if (result != OK) {
        if (rs_verbose) {
            printf("RS: %s initialization error: %s\n", srv_to_string(rp),
                init_strerror(result));
        }
        if (result == ERESTART && !SRV_IS_UPDATING(rp)) {
            rp->r_flags |= RS_REINCARNATE;
        }
        crash_service(rp);
        rp->r_init_err = result;
        return EDONTREPLY;
    }

    if (rs_verbose) {
        printf("RS: %s initialized\n", srv_to_string(rp));
    }

    if (SRV_IS_UPDATING(rp)) {
        handle_update_completion(rp);
    } else {
        handle_normal_initialization(rp, rpub);
    }

    return EDONTREPLY;
}

static void handle_update_completion(struct rproc *rp)
{
    rupdate.num_init_ready_pending--;
    rp->r_flags |= RS_INIT_DONE;
    
    if (rupdate.num_init_ready_pending == 0) {
        printf("RS: update succeeded\n");
        end_update(OK, RS_REPLY);
    }
}

static void handle_normal_initialization(struct rproc *rp, struct rprocpub *rpub)
{
    message m;
    
    rp->r_flags &= ~RS_INITIALIZING;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();
    
    m.m_type = OK;
    reply(rpub->endpoint, rp, &m);
    
    end_srv_init(rp);
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
    char label[RS_MAX_LABEL_LEN];
    int s;
    
    s = copy_rs_start(m_ptr->m_source, m_ptr->m_rs_req.addr, &rs_start);
    if (s != OK) {
        return s;
    }
    
    s = copy_label(m_ptr->m_source, rs_start.rss_label.l_addr,
        rs_start.rss_label.l_len, label, sizeof(label));
    if (s != OK) {
        return s;
    }
    
    rp = lookup_slot_by_label(label);
    if (!rp) {
        if (rs_verbose)
            printf("RS: do_update: service '%s' not found\n", label);
        return ESRCH;
    }
    rpub = rp->r_pub;
    
    struct update_flags {
        int noblock;
        int do_self_update;
        int force_self_update;
        int batch_mode;
        int prepare_only;
        int lu_flags;
        int init_flags;
        int allow_retries;
    } flags = {0};
    
    s = parse_update_flags(&rs_start, &flags);
    if (s != OK) {
        return s;
    }
    
    endpoint_t state_endpoint = NONE;
    trg_rp = NULL;
    if (rs_start.rss_trg_label.l_len > 0) {
        s = lookup_target_service(m_ptr, &rs_start, &trg_rp);
        if (s != OK) {
            return s;
        }
        state_endpoint = trg_rp->r_pub->endpoint;
    }
    
    s = check_call_permission(m_ptr->m_source, RS_UPDATE, rp);
    if (s != OK) {
        return s;
    }
    
    int prepare_state = m_ptr->m_rs_update.state;
    if (prepare_state == SEF_LU_STATE_NULL) {
        return EINVAL;
    }
    
    int prepare_maxtime = m_ptr->m_rs_update.prepare_maxtime;
    if (prepare_maxtime == 0) {
        prepare_maxtime = RS_DEFAULT_PREPARE_MAXTIME;
    }
    
    s = validate_update_state(rp, &flags, prepare_state);
    if (s != OK) {
        return s;
    }
    
    rpupd = &rp->r_upd;
    rupdate_upd_init(rpupd, rp);
    rpupd->lu_flags |= flags.lu_flags;
    rpupd->init_flags |= flags.init_flags;
    rupdate_set_new_upd_flags(rpupd);
    
    if (!flags.prepare_only) {
        s = prepare_new_version(rp, &rs_start, &flags, m_ptr, rpupd, &new_rp);
        if (s != OK) {
            return s;
        }
        
        if (state_endpoint == NONE) {
            state_endpoint = new_rp->r_pub->endpoint;
        }
        
        s = setup_new_instance(rp, new_rp, &rs_start);
        if (s != OK) {
            cleanup_service(new_rp);
            return s;
        }
    }
    
    s = process_state_data(m_ptr, prepare_state, &rs_start, rpupd, rpub);
    if (s != OK) {
        rupdate_upd_clear(rpupd);
        return s;
    }
    
    rpupd->prepare_state = prepare_state;
    rpupd->state_endpoint = state_endpoint;
    rpupd->prepare_tm = getticks();
    rpupd->prepare_maxtime = prepare_maxtime;
    rupdate_add_upd(rpupd);
    
    if (rs_verbose)
        printf("RS: %s scheduled for %s\n", srv_to_string(rp), srv_upd_to_string(rpupd));
    
    if (flags.batch_mode) {
        return OK;
    }
    
    s = start_update_prepare(flags.allow_retries);
    if (s == ESRCH) {
        return OK;
    }
    if (s != OK) {
        return s;
    }
    
    if (flags.noblock) {
        return OK;
    }
    
    rupdate.last_rpupd->rp->r_flags |= RS_LATEREPLY;
    rupdate.last_rpupd->rp->r_caller = m_ptr->m_source;
    rupdate.last_rpupd->rp->r_caller_request = RS_UPDATE;
    
    return EDONTREPLY;
}

static int parse_update_flags(struct rs_start *rs_start, struct update_flags *flags)
{
    flags->noblock = (rs_start->rss_flags & RSS_NOBLOCK) != 0;
    flags->do_self_update = (rs_start->rss_flags & RSS_SELF_LU) != 0;
    flags->force_self_update = (rs_start->rss_flags & RSS_FORCE_SELF_LU) != 0;
    flags->batch_mode = (rs_start->rss_flags & RSS_BATCH) != 0;
    flags->prepare_only = (rs_start->rss_flags & RSS_PREPARE_ONLY_LU) != 0;
    flags->allow_retries = 0;
    
    if (flags->do_self_update || flags->force_self_update) {
        flags->lu_flags |= SEF_LU_SELF;
    }
    if (flags->prepare_only) {
        flags->lu_flags |= SEF_LU_PREPARE_ONLY;
    }
    if (rs_start->rss_flags & RSS_ASR_LU) {
        flags->lu_flags |= SEF_LU_ASR;
    }
    if (!flags->prepare_only && (rs_start->rss_flags & RSS_DETACH)) {
        flags->lu_flags |= SEF_LU_DETACHED;
    }
    if ((rs_start->rss_flags & RSS_NOMMAP_LU) || rs_start->rss_map_prealloc_bytes) {
        flags->lu_flags |= SEF_LU_NOMMAP;
    }
    if (rs_start->rss_flags & RSS_FORCE_INIT_CRASH) {
        flags->init_flags |= SEF_INIT_CRASH;
    }
    if (rs_start->rss_flags & RSS_FORCE_INIT_FAIL) {
        flags->init_flags |= SEF_INIT_FAIL;
    }
    if (rs_start->rss_flags & RSS_FORCE_INIT_TIMEOUT) {
        flags->init_flags |= SEF_INIT_TIMEOUT;
    }
    if (rs_start->rss_flags & RSS_FORCE_INIT_DEFCB) {
        flags->init_flags |= SEF_INIT_DEFCB;
    }
    if (rs_start->rss_flags & RSS_FORCE_INIT_ST) {
        flags->init_flags |= SEF_INIT_ST;
    }
    flags->init_flags |= flags->lu_flags;
    
    return OK;
}

static int lookup_target_service(message *m_ptr, struct rs_start *rs_start, struct rproc **trg_rp)
{
    char label[RS_MAX_LABEL_LEN];
    int s;
    
    s = copy_label(m_ptr->m_source, rs_start->rss_trg_label.l_addr,
        rs_start->rss_trg_label.l_len, label, sizeof(label));
    if (s != OK) {
        return s;
    }
    
    *trg_rp = lookup_slot_by_label(label);
    if (!*trg_rp) {
        if (rs_verbose)
            printf("RS: do_update: target service '%s' not found\n", label);
        return ESRCH;
    }
    
    return OK;
}

static int validate_update_state(struct rproc *rp, struct update_flags *flags, int prepare_state)
{
    if (RUPDATE_IS_UPDATING()) {
        printf("RS: an update is already in progress\n");
        return EBUSY;
    }
    
    if (RUPDATE_IS_UPD_SCHEDULED()) {
        if (!flags->batch_mode) {
            printf("RS: an update is already scheduled, cannot start a new one\n");
            return EBUSY;
        }
        if (SRV_IS_UPD_SCHEDULED(rp)) {
            printf("RS: the specified process is already part of the currently scheduled update\n");
            return EINVAL;
        }
    }
    
    if (flags->prepare_only) {
        endpoint_t ep = rp->r_pub->endpoint;
        if ((ep == VM_PROC_NR || ep == PM_PROC_NR || ep == VFS_PROC_NR) 
            && prepare_state != SEF_LU_STATE_UNREACHABLE) {
            printf("RS: prepare-only update for VM, PM and VFS is only supported with state %d\n", 
                SEF_LU_STATE_UNREACHABLE);
            return EINVAL;
        }
        if (ep == RS_PROC_NR) {
            printf("RS: prepare-only update for RS is not supported\n");
            return EINVAL;
        }
    }
    
    return OK;
}

static int prepare_new_version(struct rproc *rp, struct rs_start *rs_start, 
    struct update_flags *flags, message *m_ptr, struct rprocupd *rpupd, 
    struct rproc **new_rp)
{
    int s;
    
    if (flags->do_self_update) {
        if (rs_verbose)
            printf("RS: %s requested to perform self update\n", srv_to_string(rp));
        
        s = clone_service(rp, LU_SYS_PROC, rpupd->init_flags);
        if (s != OK) {
            printf("RS: do_update: unable to clone service: %d\n", s);
            return s;
        }
        *new_rp = rp->r_new_rp;
    } else {
        if (rs_verbose)
            printf("RS: %s requested to perform %s update\n", srv_to_string(rp),
                flags->force_self_update ? "(forced) self" : "regular");
        
        s = alloc_slot(new_rp);
        if (s != OK) {
            printf("RS: do_update: unable to allocate a new slot: %d\n", s);
            return s;
        }
        
        s = init_slot(*new_rp, rs_start, m_ptr->m_source);
        if (s != OK) {
            printf("RS: do_update: unable to init the new slot: %d\n", s);
            return s;
        }
        
        inherit_service_defaults(rp, *new_rp);
        
        rp->r_new_rp = *new_rp;
        (*new_rp)->r_old_rp = rp;
        
        (*new_rp)->r_priv.s_flags |= LU_SYS_PROC;
        (*new_rp)->r_priv.s_init_flags |= rpupd->init_flags;
        s = create_service(*new_rp);
        if (s != OK) {
            printf("RS: do_update: unable to create a new service: %d\n", s);
            return s;
        }
    }
    
    check_vm_preallocation(rp, rs_start, flags);
    
    return OK;
}

static void check_vm_preallocation(struct rproc *rp, struct rs_start *rs_start, 
    struct update_flags *flags)
{
    if (rs_start->rss_map_prealloc_bytes <= 0
        && rp->r_pub->endpoint == VM_PROC_NR
        && (((flags->lu_flags & (SEF_LU_SELF|SEF_LU_ASR)) != SEF_LU_SELF) 
            || rs_start->rss_flags & RSS_FORCE_INIT_ST)
        && RS_VM_DEFAULT_MAP_PREALLOC_LEN > 0) {
        rs_start->rss_map_prealloc_bytes = RS_VM_DEFAULT_MAP_PREALLOC_LEN;
        if (rs_verbose)
            printf("RS: %s gets %ld default mmap bytes\n", srv_to_string(rp),
                rs_start->rss_map_prealloc_bytes);
    }
}

static int setup_new_instance(struct rproc *rp, struct rproc *new_rp, 
    struct rs_start *rs_start)
{
    int s;
    
    if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
        s = update_sig_mgrs(new_rp, SELF, new_rp->r_pub->endpoint);
        if (s != OK) {
            return s;
        }
    }
    
    s = preallocate_heap(new_rp, rs_start);
    if (s != OK) {
        return s;
    }
    
    s = preallocate_mmap(new_rp, rs_start);
    if (s != OK) {
        return s;
    }
    
    return OK;
}

static int preallocate_heap(struct rproc *new_rp, struct rs_start *rs_start)
{
    int s;
    size_t len;
    
    if (rs_start->rss_heap_prealloc_bytes < 0) {
        rs_start->rss_heap_prealloc_bytes = 0;
    }
    
    if (rs_start->rss_heap_prealloc_bytes == 0) {
        return OK;
    }
    
    if (rs_verbose)
        printf("RS: %s preallocating %ld heap bytes\n", srv_to_string(new_rp),
            rs_start->rss_heap_prealloc_bytes);
    
    len = rs_start->rss_heap_prealloc_bytes;
    s = vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_HEAP_PREALLOC, NULL, &len);
    if (s != OK) {
        printf("vm_memctl(VM_RS_MEM_HEAP_PREALLOC) failed: %d\n", s);
        return s;
    }
    
    if (new_rp->r_old_rp && (new_rp->r_old_rp->r_priv.s_flags & ROOT_SYS_PROC)) {
        vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
    }
    
    return OK;
}

static int preallocate_mmap(struct rproc *new_rp, struct rs_start *rs_start)
{
    int s;
    void *addr = NULL;
    
    if (rs_start->rss_map_prealloc_bytes < 0) {
        rs_start->rss_map_prealloc_bytes = 0;
    }
    
    if (rs_start->rss_map_prealloc_bytes == 0) {
        return OK;
    }
    
    if (rs_verbose)
        printf("RS: %s preallocating %ld mmap bytes\n", srv_to_string(new_rp),
            rs_start->rss_map_prealloc_bytes);
    
    new_rp->r_map_prealloc_len = rs_start->rss_map_prealloc_bytes;
    s = vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_MAP_PREALLOC,
        &addr, &new_rp->r_map_prealloc_len);
    if (s != OK) {
        printf("vm_memctl(VM_RS_MEM_MAP_PREALLOC) failed: %d\n", s);
        return s;
    }
    
    new_rp->r_map_prealloc_addr = (vir_bytes) addr;
    return OK;
}

static int process_state_data(message *m_ptr, int prepare_state, 
    struct rs_start *rs_start, struct rprocupd *rpupd, struct rprocpub *rpub)
{
    int s;
    
    s = init_state_data(m_ptr->m_source, prepare_state, 
        &rs_start->rss_state_data, &rpupd->prepare_state_data);
    if (s != OK) {
        return s;
    }
    
    if (rpupd->prepare_state_data.size > 0) {
        s = create_state_grants(rpupd, rpub);
        if (s != OK) {
            return s;
        }
    }
    
    return OK;
}

static int create_state_grants(struct rprocupd *rpupd, struct rprocpub *rpub)
{
    struct rs_state_data *state_data = &rpupd->prepare_state_data;
    
    rpupd->prepare_state_data_gid = cpf_grant_direct(rpub->endpoint, 
        (vir_bytes) state_data, state_data->size, CPF_READ);
    if (rpupd->prepare_state_data_gid == GRANT_INVALID) {
        return ENOMEM;
    }
    
    state_data->ipcf_els_gid = GRANT_INVALID;
    if (state_data->ipcf_els) {
        state_data->ipcf_els_gid = (int) cpf_grant_direct(rpub->endpoint, 
            (vir_bytes) state_data->ipcf_els, state_data->ipcf_els_size, CPF_READ);
        if (state_data->ipcf_els_gid == GRANT_INVALID) {
            return ENOMEM;
        }
    }
    
    state_data->eval_gid = GRANT_INVALID;
    if (state_data->eval_addr) {
        state_data->eval_gid = (int) cpf_grant_direct(rpub->endpoint, 
            (vir_bytes) state_data->eval_addr, state_data->eval_len, CPF_READ);
        if (state_data->eval_gid == GRANT_INVALID) {
            return ENOMEM;
        }
    }
    
    return OK;
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

    if (!m_ptr) {
        return EINVAL;
    }

    who_p = _ENDPOINT_P(m_ptr->m_source);
    if (who_p < 0 || who_p >= NR_SYS_PROCS) {
        return EINVAL;
    }

    rp = rproc_ptr[who_p];
    if (!rp) {
        return EINVAL;
    }

    result = m_ptr->m_rs_update.result;
    rpupd = rupdate.curr_rpupd;

    if (!rpupd || rp != rpupd->rp || RUPDATE_IS_INITIALIZING()) {
        if (rs_verbose) {
            printf("RS: %s sent late/unexpected update ready msg\n",
                srv_to_string(rp));
        }
        return EINVAL;
    }

    rp->r_flags |= RS_PREPARE_DONE;

    if (result != OK) {
        printf("RS: update failed: %s\n", lu_strerror(result));
        end_update(result, RS_REPLY);
        return EDONTREPLY;
    }

    if (rs_verbose) {
        printf("RS: %s ready to update\n", srv_to_string(rp));
    }

    if (start_update_prepare_next() != NULL) {
        return EDONTREPLY;
    }

    start_update();

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
void do_sigchld()
{
    pid_t pid;
    int status;
    struct rproc *rp;
    struct rproc **rps;
    int i, nr_rps;
    int found = 0;

    if (rs_verbose) {
        printf("RS: got SIGCHLD signal, cleaning up dead children\n");
    }

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        rp = lookup_slot_by_pid(pid);
        if (rp == NULL) {
            continue;
        }

        if (rs_verbose) {
            printf("RS: %s exited via another signal manager\n",
                srv_to_string(rp));
        }

        process_service_instances(rp, &found);
    }
}

static void process_service_instances(struct rproc *rp, int *found)
{
    struct rproc **rps = NULL;
    int nr_rps = 0;
    int i;

    get_service_instances(rp, &rps, &nr_rps);
    
    for (i = 0; i < nr_rps; i++) {
        if (rps[i] == NULL) {
            continue;
        }
        
        if (SRV_IS_UPDATING(rps[i])) {
            clear_update_flags(rps[i]);
            *found = 1;
        }
        free_slot(rps[i]);
    }
    
    if (*found) {
        rupdate_clear_upds();
        *found = 0;
    }
}

static void clear_update_flags(struct rproc *rp)
{
    if (rp == NULL) {
        return;
    }
    
    rp->r_flags &= ~(RS_UPDATING | RS_PREPARE_DONE | RS_INIT_DONE | RS_INIT_PENDING);
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
	int request_type = m_ptr->m_rs_req.subtype;
	int r;
	int allow_retries = 1;

	switch(request_type) {
		case RS_SYSCTL_SRV_STATUS:
			print_services_status();
			return OK;

		case RS_SYSCTL_UPD_START:
			r = start_update_prepare(allow_retries);
			print_update_status();
			if(r != OK) {
				if(r == ESRCH) {
					return OK;
				}
				return r;
			}
			return OK;

		case RS_SYSCTL_UPD_RUN:
			r = start_update_prepare(allow_retries);
			print_update_status();
			if(r != OK) {
				if(r == ESRCH) {
					return OK;
				}
				return r;
			}
			rupdate.last_rpupd->rp->r_flags |= RS_LATEREPLY;
			rupdate.last_rpupd->rp->r_caller = m_ptr->m_source;
			rupdate.last_rpupd->rp->r_caller_request = RS_UPDATE;
			return EDONTREPLY;

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
    struct rproc *rp;
    char label[RS_MAX_LABEL_LEN];
    int result;

    result = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
        m_ptr->m_rs_req.len, label, sizeof(label));
    if (result != OK) {
        return result;
    }

    rp = lookup_slot_by_label(label);
    if (!rp) {
        if (rs_verbose) {
            printf("RS: do_fi: service '%s' not found\n", label);
        }
        return ESRCH;
    }

    result = check_call_permission(m_ptr->m_source, RS_FI, rp);
    if (result != OK) {
        return result;
    }

    return fi_service(rp);
}

/*===========================================================================*
 *				   check_request			     *
 *===========================================================================*/
static int check_request(struct rs_start *rs_start)
{
  if (rs_start == NULL) {
    return EINVAL;
  }

  if (rs_start->rss_scheduler != KERNEL) {
    if (rs_start->rss_scheduler < 0 || rs_start->rss_scheduler > LAST_SPECIAL_PROC_NR) {
      printf("RS: check_request: invalid scheduler %d\n", rs_start->rss_scheduler);
      return EINVAL;
    }
  }

  if (rs_start->rss_priority >= NR_SCHED_QUEUES) {
    printf("RS: check_request: priority %u out of range\n", rs_start->rss_priority);
    return EINVAL;
  }

  if (rs_start->rss_quantum <= 0) {
    printf("RS: check_request: quantum %u out of range\n", rs_start->rss_quantum);
    return EINVAL;
  }

  if (rs_start->rss_cpu == RS_CPU_BSP) {
    rs_start->rss_cpu = machine.bsp_id;
  } else if (rs_start->rss_cpu != RS_CPU_DEFAULT) {
    if (rs_start->rss_cpu < 0) {
      return EINVAL;
    }
    if (rs_start->rss_cpu > machine.processors_count) {
      printf("RS: cpu number %d out of range 0-%d, using BSP\n",
              rs_start->rss_cpu, machine.processors_count);
      rs_start->rss_cpu = machine.bsp_id;
    }
  }

  if (rs_start->rss_sigmgr != SELF) {
    if (rs_start->rss_sigmgr < 0 || rs_start->rss_sigmgr > LAST_SPECIAL_PROC_NR) {
      printf("RS: check_request: invalid signal manager %d\n", rs_start->rss_sigmgr);
      return EINVAL;
    }
  }

  return OK;
}

