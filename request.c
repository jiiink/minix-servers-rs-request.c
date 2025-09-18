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
  register struct rproc *rp;
  int s;
  char label[RS_MAX_LABEL_LEN];

  s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if(s != OK) {
      return s;
  }

  rp = lookup_slot_by_label(label);
  if(!rp) {
      if(rs_verbose)
          printf("RS: do_down: service '%s' not found\n", label);
      return(ESRCH);
  }

  s = check_call_permission(m_ptr->m_source, RS_DOWN, rp);
  if(s != OK)
      return s;

  if (rp->r_flags & RS_TERMINATED) {
      return handle_terminated_service(rp);
  }

  return handle_active_service(rp, m_ptr->m_source);
}

static int handle_terminated_service(struct rproc *rp)
{
  if(rs_verbose)
      printf("RS: recovery script performs service down...\n");
  unpublish_service(rp);
  cleanup_service(rp);
  return(OK);
}

static int handle_active_service(struct rproc *rp, int source)
{
  stop_service(rp, RS_EXITING);
  rp->r_flags |= RS_LATEREPLY;
  rp->r_caller = source;
  rp->r_caller_request = RS_DOWN;
  return EDONTREPLY;
}

/*===========================================================================*
 *				do_restart				     *
 *===========================================================================*/
int do_restart(message *m_ptr)
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
      if(rs_verbose)
          printf("RS: do_restart: service '%s' not found\n", label);
      return ESRCH;
  }

  s = check_call_permission(m_ptr->m_source, RS_RESTART, rp);
  if(s != OK)
      return s;

  if(!(rp->r_flags & RS_TERMINATED)) {
      if(rs_verbose)
          printf("RS: %s is still running\n", srv_to_string(rp));
      return EBUSY;
  }

  if(rs_verbose)
      printf("RS: recovery script performs service restart...\n");

  perform_restart_without_script(rp);

  return OK;
}

static void perform_restart_without_script(struct rproc *rp)
{
  char script[MAX_SCRIPT_LEN];
  
  strcpy(script, rp->r_script);
  rp->r_script[0] = '\0';
  restart_service(rp);
  strcpy(rp->r_script, script);
}

/*===========================================================================*
 *				do_clone				     *
 *===========================================================================*/
int do_clone(message *m_ptr)
{
    char label[RS_MAX_LABEL_LEN];
    int s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
                       m_ptr->m_rs_req.len, label, sizeof(label));
    if(s != OK) {
        return s;
    }

    struct rproc *rp = lookup_slot_by_label(label);
    if(!rp) {
        if(rs_verbose)
            printf("RS: do_clone: service '%s' not found\n", label);
        return ESRCH;
    }

    int r = check_call_permission(m_ptr->m_source, RS_CLONE, rp);
    if(r != OK) {
        return r;
    }

    if(rp->r_next_rp) {
        return EEXIST;
    }

    struct rprocpub *rpub = rp->r_pub;
    rpub->sys_flags |= SF_USE_REPL;
    
    r = clone_service(rp, RST_SYS_PROC, 0);
    if(r != OK) {
        rpub->sys_flags &= ~SF_USE_REPL;
        return r;
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
  int s, r;
  char label[RS_MAX_LABEL_LEN];

  s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if(s != OK) {
      return s;
  }

  rp = lookup_slot_by_label(label);
  if(!rp) {
      if(rs_verbose)
          printf("RS: do_unclone: service '%s' not found\n", label);
      return(ESRCH);
  }
  rpub = rp->r_pub;

  if((r = check_call_permission(m_ptr->m_source, RS_UNCLONE, rp)) != OK)
      return r;

  if(!(rpub->sys_flags & SF_USE_REPL)) {
      return ENOENT;
  }

  rpub->sys_flags &= ~SF_USE_REPL;
  if(rp->r_next_rp) {
      cleanup_service_now(rp->r_next_rp);
      rp->r_next_rp = NULL;
  }

  return OK;
}

/*===========================================================================*
 *				    do_edit				     *
 *===========================================================================*/
#define ERROR_MSG_SYNCH_PRIV "RS: do_edit: unable to synch privilege structure: %d\n"
#define ERROR_MSG_SCHED_STOP "RS: do_edit: scheduler won't give up process: %d\n"
#define ERROR_MSG_EDIT_SLOT "RS: do_edit: unable to edit the existing slot: %d\n"
#define ERROR_MSG_UPDATE_PRIV "RS: do_edit: unable to update privilege structure: %d\n"
#define ERROR_MSG_VM_SET_PRIV "RS: do_edit: failed: %d\n"
#define ERROR_MSG_REINIT_SCHED "RS: do_edit: unable to reinitialize scheduling: %d\n"
#define ERROR_MSG_SERVICE_NOT_FOUND "RS: do_edit: service '%s' not found\n"
#define ERROR_MSG_CLONE_WARNING "RS: warning: unable to clone %s\n"

static int copy_request_data(message *m_ptr, struct rs_start *rs_start, char *label, size_t label_size)
{
    int r;
    
    r = copy_rs_start(m_ptr->m_source, m_ptr->m_rs_req.addr, rs_start);
    if (r != OK) {
        return r;
    }
    
    r = copy_label(m_ptr->m_source, rs_start->rss_label.l_addr,
        rs_start->rss_label.l_len, label, label_size);
    return r;
}

static int sync_privilege(struct rproc *rp)
{
    int r = sys_getpriv(&rp->r_priv, rp->r_pub->endpoint);
    if (r != OK) {
        printf(ERROR_MSG_SYNCH_PRIV, r);
    }
    return r;
}

static int stop_scheduler(struct rproc *rp)
{
    int r = sched_stop(rp->r_scheduler, rp->r_pub->endpoint);
    if (r != OK) {
        printf(ERROR_MSG_SCHED_STOP, r);
    }
    return r;
}

static int perform_edit(struct rproc *rp, struct rs_start *rs_start, endpoint_t source)
{
    int r = edit_slot(rp, rs_start, source);
    if (r != OK) {
        printf(ERROR_MSG_EDIT_SLOT, r);
    }
    return r;
}

static int update_privileges(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;
    int r;
    
    r = sys_privctl(rpub->endpoint, SYS_PRIV_UPDATE_SYS, &rp->r_priv);
    if (r != OK) {
        printf(ERROR_MSG_UPDATE_PRIV, r);
        return r;
    }
    
    r = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0],
        !!(rp->r_priv.s_flags & SYS_PROC));
    if (r != OK) {
        printf(ERROR_MSG_VM_SET_PRIV, r);
    }
    return r;
}

static int reinitialize_scheduling(struct rproc *rp)
{
    int r = sched_init_proc(rp);
    if (r != OK) {
        printf(ERROR_MSG_REINIT_SCHED, r);
    }
    return r;
}

static void handle_replicas(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;
    int r;
    
    if (!(rpub->sys_flags & SF_USE_REPL)) {
        return;
    }
    
    if (rp->r_next_rp) {
        cleanup_service(rp->r_next_rp);
        rp->r_next_rp = NULL;
    }
    
    if ((r = clone_service(rp, RST_SYS_PROC, 0)) != OK) {
        printf(ERROR_MSG_CLONE_WARNING, srv_to_string(rp));
    }
}

int do_edit(message *m_ptr)
{
    struct rproc *rp;
    struct rs_start rs_start;
    int r;
    char label[RS_MAX_LABEL_LEN];
    
    r = copy_request_data(m_ptr, &rs_start, label, sizeof(label));
    if (r != OK) {
        return r;
    }
    
    rp = lookup_slot_by_label(label);
    if (!rp) {
        if (rs_verbose) {
            printf(ERROR_MSG_SERVICE_NOT_FOUND, label);
        }
        return ESRCH;
    }
    
    r = check_call_permission(m_ptr->m_source, RS_EDIT, rp);
    if (r != OK) {
        return r;
    }
    
    if (rs_verbose) {
        printf("RS: %s edits settings\n", srv_to_string(rp));
    }
    
    r = sync_privilege(rp);
    if (r != OK) {
        return r;
    }
    
    r = stop_scheduler(rp);
    if (r != OK) {
        return r;
    }
    
    r = perform_edit(rp, &rs_start, m_ptr->m_source);
    if (r != OK) {
        return r;
    }
    
    r = update_privileges(rp);
    if (r != OK) {
        return r;
    }
    
    r = reinitialize_scheduling(rp);
    if (r != OK) {
        return r;
    }
    
    handle_replicas(rp);
    
    return OK;
}

/*===========================================================================*
 *				do_refresh				     *
 *===========================================================================*/
int do_refresh(message *m_ptr)
{
  char label[RS_MAX_LABEL_LEN];
  int s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if(s != OK) {
      return s;
  }

  register struct rproc *rp = lookup_slot_by_label(label);
  if(!rp) {
      if(rs_verbose)
          printf("RS: do_refresh: service '%s' not found\n", label);
      return(ESRCH);
  }

  s = check_call_permission(m_ptr->m_source, RS_REFRESH, rp);
  if(s != OK)
      return s;

  if(rs_verbose)
      printf("RS: %s refreshing\n", srv_to_string(rp));
  stop_service(rp,RS_REFRESHING);

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
    int r;

    if (m_ptr != NULL) {
        r = check_call_permission(m_ptr->m_source, RS_SHUTDOWN, NULL);
        if (r != OK)
            return r;
    }

    if (rs_verbose)
        printf("RS: shutting down...\n");

    shutting_down = TRUE;

    mark_all_services_as_exiting();
    
    return OK;
}

static void mark_all_services_as_exiting(void)
{
    int slot_nr;
    struct rproc *rp;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        if (rp->r_flags & RS_IN_USE) {
            rp->r_flags |= RS_EXITING;
        }
    }
}

/*===========================================================================*
 *				do_init_ready				     *
 *===========================================================================*/
#define INIT_READY_SUCCESS OK
#define NO_SERVICE_UPDATE_LEFT 0

static int validate_initialization_request(struct rproc *rp, endpoint_t source)
{
    if (!(rp->r_flags & RS_INITIALIZING)) {
        if (rs_verbose)
            printf("RS: do_init_ready: got unexpected init ready msg from %d\n", source);
        return EINVAL;
    }
    return OK;
}

static int handle_initialization_failure(struct rproc *rp, int result)
{
    if (rs_verbose)
        printf("RS: %s initialization error: %s\n", srv_to_string(rp), init_strerror(result));
    
    if (result == ERESTART && !SRV_IS_UPDATING(rp))
        rp->r_flags |= RS_REINCARNATE;
    
    crash_service(rp);
    rp->r_init_err = result;
    return EDONTREPLY;
}

static void complete_update_process(struct rproc *rp)
{
    rupdate.num_init_ready_pending--;
    rp->r_flags |= RS_INIT_DONE;
    
    if (rupdate.num_init_ready_pending == NO_SERVICE_UPDATE_LEFT) {
        printf("RS: update succeeded\n");
        end_update(OK, RS_REPLY);
    }
}

static void finalize_normal_initialization(struct rproc *rp)
{
    message m;
    
    rp->r_flags &= ~RS_INITIALIZING;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();
    
    m.m_type = OK;
    reply(rp->r_pub->endpoint, rp, &m);
    
    end_srv_init(rp);
}

int do_init_ready(message *m_ptr)
{
    int who_p;
    struct rproc *rp;
    int result;
    int validation_result;

    who_p = _ENDPOINT_P(m_ptr->m_source);
    result = m_ptr->m_rs_init.result;
    rp = rproc_ptr[who_p];

    validation_result = validate_initialization_request(rp, m_ptr->m_source);
    if (validation_result != OK)
        return validation_result;

    if (result != INIT_READY_SUCCESS)
        return handle_initialization_failure(rp, result);

    if (rs_verbose)
        printf("RS: %s initialized\n", srv_to_string(rp));

    if (SRV_IS_UPDATING(rp)) {
        complete_update_process(rp);
    } else {
        finalize_normal_initialization(rp);
    }

    return EDONTREPLY;
}

/*===========================================================================*
 *				do_update				     *
 *===========================================================================*/
#define RS_VM_DEFAULT_MAP_PREALLOC_LEN 0
#define RS_DEFAULT_PREPARE_MAXTIME 0

static int copy_update_request(message *m_ptr, struct rs_start *rs_start, char *label)
{
    int s = copy_rs_start(m_ptr->m_source, m_ptr->m_rs_req.addr, rs_start);
    if (s != OK) return s;
    
    return copy_label(m_ptr->m_source, rs_start->rss_label.l_addr,
        rs_start->rss_label.l_len, label, RS_MAX_LABEL_LEN);
}

static struct rproc* find_service_by_label(char *label)
{
    struct rproc *rp = lookup_slot_by_label(label);
    if (!rp && rs_verbose) {
        printf("RS: do_update: service '%s' not found\n", label);
    }
    return rp;
}

static void set_lu_flags(struct rs_start *rs_start, int *lu_flags)
{
    if (rs_start->rss_flags & (RSS_SELF_LU | RSS_FORCE_SELF_LU)) {
        *lu_flags |= SEF_LU_SELF;
    }
    if (rs_start->rss_flags & RSS_PREPARE_ONLY_LU) {
        *lu_flags |= SEF_LU_PREPARE_ONLY;
    }
    if (rs_start->rss_flags & RSS_ASR_LU) {
        *lu_flags |= SEF_LU_ASR;
    }
    if (!(rs_start->rss_flags & RSS_PREPARE_ONLY_LU) && (rs_start->rss_flags & RSS_DETACH)) {
        *lu_flags |= SEF_LU_DETACHED;
    }
    if ((rs_start->rss_flags & RSS_NOMMAP_LU) || rs_start->rss_map_prealloc_bytes) {
        *lu_flags |= SEF_LU_NOMMAP;
    }
}

static void set_init_flags(struct rs_start *rs_start, int lu_flags, int *init_flags)
{
    if (rs_start->rss_flags & RSS_FORCE_INIT_CRASH) *init_flags |= SEF_INIT_CRASH;
    if (rs_start->rss_flags & RSS_FORCE_INIT_FAIL) *init_flags |= SEF_INIT_FAIL;
    if (rs_start->rss_flags & RSS_FORCE_INIT_TIMEOUT) *init_flags |= SEF_INIT_TIMEOUT;
    if (rs_start->rss_flags & RSS_FORCE_INIT_DEFCB) *init_flags |= SEF_INIT_DEFCB;
    if (rs_start->rss_flags & RSS_FORCE_INIT_ST) *init_flags |= SEF_INIT_ST;
    *init_flags |= lu_flags;
}

static void handle_vm_mmap_defaults(struct rs_start *rs_start, struct rproc *rp, int lu_flags)
{
    if (rs_start->rss_map_prealloc_bytes <= 0 && 
        rp->r_pub->endpoint == VM_PROC_NR &&
        (((lu_flags & (SEF_LU_SELF|SEF_LU_ASR)) != SEF_LU_SELF) || 
         rs_start->rss_flags & RSS_FORCE_INIT_ST) &&
        RS_VM_DEFAULT_MAP_PREALLOC_LEN > 0) {
        
        rs_start->rss_map_prealloc_bytes = RS_VM_DEFAULT_MAP_PREALLOC_LEN;
        if (rs_verbose) {
            printf("RS: %s gets %ld default mmap bytes\n", 
                srv_to_string(rp), rs_start->rss_map_prealloc_bytes);
        }
    }
}

static int find_target_service(message *m_ptr, struct rs_start *rs_start, 
    struct rproc **trg_rp, endpoint_t *state_endpoint)
{
    char label[RS_MAX_LABEL_LEN];
    *trg_rp = NULL;
    *state_endpoint = NONE;
    
    if (rs_start->rss_trg_label.l_len <= 0) return OK;
    
    int s = copy_label(m_ptr->m_source, rs_start->rss_trg_label.l_addr,
        rs_start->rss_trg_label.l_len, label, sizeof(label));
    if (s != OK) return s;
    
    *trg_rp = lookup_slot_by_label(label);
    if (!*trg_rp) {
        if (rs_verbose) {
            printf("RS: do_update: target service '%s' not found\n", label);
        }
        return ESRCH;
    }
    *state_endpoint = (*trg_rp)->r_pub->endpoint;
    return OK;
}

static int validate_update_constraints(struct rproc *rp, int batch_mode, int prepare_only, int prepare_state)
{
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
    
    endpoint_t ep = rp->r_pub->endpoint;
    if (prepare_only && (ep == VM_PROC_NR || ep == PM_PROC_NR || ep == VFS_PROC_NR)) {
        if (prepare_state != SEF_LU_STATE_UNREACHABLE) {
            printf("RS: prepare-only update for VM, PM and VFS is only supported with state %d\n", 
                SEF_LU_STATE_UNREACHABLE);
            return EINVAL;
        }
    }
    
    if (prepare_only && ep == RS_PROC_NR) {
        printf("RS: prepare-only update for RS is not supported\n");
        return EINVAL;
    }
    
    return OK;
}

static int create_new_version(struct rproc *rp, struct rs_start *rs_start, 
    message *m_ptr, struct rprocupd *rpupd, int do_self_update, int force_self_update)
{
    struct rproc *new_rp;
    int s;
    
    if (do_self_update) {
        if (rs_verbose) {
            printf("RS: %s requested to perform self update\n", srv_to_string(rp));
        }
        s = clone_service(rp, LU_SYS_PROC, rpupd->init_flags);
        if (s != OK) {
            printf("RS: do_update: unable to clone service: %d\n", s);
            return s;
        }
    } else {
        if (rs_verbose) {
            printf("RS: %s requested to perform %s update\n", srv_to_string(rp),
                force_self_update ? "(forced) self" : "regular");
        }
        
        s = alloc_slot(&new_rp);
        if (s != OK) {
            printf("RS: do_update: unable to allocate a new slot: %d\n", s);
            return s;
        }
        
        s = init_slot(new_rp, rs_start, m_ptr->m_source);
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
    return OK;
}

static int setup_signal_managers(struct rproc *rp, struct rproc *new_rp)
{
    if (!(rp->r_priv.s_flags & ROOT_SYS_PROC)) return OK;
    
    int s = update_sig_mgrs(new_rp, SELF, new_rp->r_pub->endpoint);
    if (s != OK) {
        cleanup_service(new_rp);
    }
    return s;
}

static int preallocate_memory(struct rproc *rp, struct rproc *new_rp, 
    struct rs_start *rs_start, const char *mem_type, int vm_flag, 
    long bytes, vir_bytes *addr_out, size_t *len_out)
{
    if (bytes <= 0) return OK;
    
    if (rs_verbose) {
        printf("RS: %s preallocating %ld %s bytes\n", 
            srv_to_string(new_rp), bytes, mem_type);
    }
    
    void *addr = NULL;
    size_t len = bytes;
    int s = vm_memctl(new_rp->r_pub->endpoint, vm_flag, 
        vm_flag == VM_RS_MEM_MAP_PREALLOC ? &addr : NULL, &len);
    
    if (s != OK) {
        printf("vm_memctl(%d) failed: %d\n", vm_flag, s);
        cleanup_service(new_rp);
        return s;
    }
    
    if (vm_flag == VM_RS_MEM_HEAP_PREALLOC && 
        (rp->r_priv.s_flags & ROOT_SYS_PROC)) {
        vm_memctl(new_rp->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
    }
    
    if (addr_out) *addr_out = (vir_bytes)addr;
    if (len_out) *len_out = len;
    
    return OK;
}

static int create_state_grant(struct rprocupd *rpupd, endpoint_t endpoint, 
    vir_bytes addr, size_t size, int *gid_out)
{
    *gid_out = GRANT_INVALID;
    if (!addr || !size) return OK;
    
    *gid_out = cpf_grant_direct(endpoint, addr, size, CPF_READ);
    if (*gid_out == GRANT_INVALID) {
        rupdate_upd_clear(rpupd);
        return ENOMEM;
    }
    return OK;
}

static int create_update_grants(struct rprocupd *rpupd, endpoint_t endpoint)
{
    if (rpupd->prepare_state_data.size <= 0) return OK;
    
    struct rs_state_data *state_data = &rpupd->prepare_state_data;
    
    rpupd->prepare_state_data_gid = cpf_grant_direct(endpoint, 
        (vir_bytes)state_data, state_data->size, CPF_READ);
    if (rpupd->prepare_state_data_gid == GRANT_INVALID) {
        rupdate_upd_clear(rpupd);
        return ENOMEM;
    }
    
    int s = create_state_grant(rpupd, endpoint, 
        (vir_bytes)state_data->ipcf_els, state_data->ipcf_els_size, 
        &state_data->ipcf_els_gid);
    if (s != OK) return s;
    
    return create_state_grant(rpupd, endpoint, 
        (vir_bytes)state_data->eval_addr, state_data->eval_len, 
        &state_data->eval_gid);
}

int do_update(message *m_ptr)
{
    struct rs_start rs_start;
    char label[RS_MAX_LABEL_LEN];
    struct rproc *rp, *trg_rp, *new_rp;
    struct rprocupd *rpupd;
    endpoint_t state_endpoint;
    int lu_flags = 0, init_flags = 0;
    int s;
    
    s = copy_update_request(m_ptr, &rs_start, label);
    if (s != OK) return s;
    
    rp = find_service_by_label(label);
    if (!rp) return ESRCH;
    
    int noblock = (rs_start.rss_flags & RSS_NOBLOCK);
    int do_self_update = (rs_start.rss_flags & RSS_SELF_LU);
    int force_self_update = (rs_start.rss_flags & RSS_FORCE_SELF_LU);
    int batch_mode = (rs_start.rss_flags & RSS_BATCH);
    int prepare_only = (rs_start.rss_flags & RSS_PREPARE_ONLY_LU);
    
    set_lu_flags(&rs_start, &lu_flags);
    handle_vm_mmap_defaults(&rs_start, rp, lu_flags);
    set_init_flags(&rs_start, lu_flags, &init_flags);
    
    s = find_target_service(m_ptr, &rs_start, &trg_rp, &state_endpoint);
    if (s != OK) return s;
    
    s = check_call_permission(m_ptr->m_source, RS_UPDATE, rp);
    if (s != OK) return s;
    
    int prepare_state = m_ptr->m_rs_update.state;
    if (prepare_state == SEF_LU_STATE_NULL) return EINVAL;
    
    int prepare_maxtime = m_ptr->m_rs_update.prepare_maxtime;
    if (prepare_maxtime == 0) {
        prepare_maxtime = RS_DEFAULT_PREPARE_MAXTIME;
    }
    
    s = validate_update_constraints(rp, batch_mode, prepare_only, prepare_state);
    if (s != OK) return s;
    
    rpupd = &rp->r_upd;
    rupdate_upd_init(rpupd, rp);
    rpupd->lu_flags |= lu_flags;
    rpupd->init_flags |= init_flags;
    rupdate_set_new_upd_flags(rpupd);
    
    if (!prepare_only) {
        s = create_new_version(rp, &rs_start, m_ptr, rpupd, 
            do_self_update, force_self_update);
        if (s != OK) return s;
        
        new_rp = rp->r_new_rp;
        
        if (state_endpoint == NONE) {
            state_endpoint = new_rp->r_pub->endpoint;
        }
        
        s = setup_signal_managers(rp, new_rp);
        if (s != OK) return s;
        
        if (rs_start.rss_heap_prealloc_bytes < 0) {
            rs_start.rss_heap_prealloc_bytes = 0;
        }
        s = preallocate_memory(rp, new_rp, &rs_start, "heap", 
            VM_RS_MEM_HEAP_PREALLOC, rs_start.rss_heap_prealloc_bytes, 
            NULL, NULL);
        if (s != OK) return s;
        
        if (rs_start.rss_map_prealloc_bytes < 0) {
            rs_start.rss_map_prealloc_bytes = 0;
        }
        s = preallocate_memory(rp, new_rp, &rs_start, "mmap", 
            VM_RS_MEM_MAP_PREALLOC, rs_start.rss_map_prealloc_bytes, 
            &new_rp->r_map_prealloc_addr, &new_rp->r_map_prealloc_len);
        if (s != OK) return s;
    }
    
    s = init_state_data(m_ptr->m_source, prepare_state, 
        &rs_start.rss_state_data, &rpupd->prepare_state_data);
    if (s != OK) {
        rupdate_upd_clear(rpupd);
        return s;
    }
    
    s = create_update_grants(rpupd, rp->r_pub->endpoint);
    if (s != OK) return s;
    
    rpupd->prepare_state = prepare_state;
    rpupd->state_endpoint = state_endpoint;
    rpupd->prepare_tm = getticks();
    rpupd->prepare_maxtime = prepare_maxtime;
    rupdate_add_upd(rpupd);
    
    if (rs_verbose) {
        printf("RS: %s scheduled for %s\n", 
            srv_to_string(rp), srv_upd_to_string(rpupd));
    }
    
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
#define RS_PREPARE_DONE_FLAG RS_PREPARE_DONE
#define UPDATE_FAILED_REPLY RS_REPLY

static int validate_update_request(struct rproc *rp, struct rprocupd *rpupd)
{
    if (!rpupd || rp != rpupd->rp || RUPDATE_IS_INITIALIZING()) {
        if (rs_verbose) {
            printf("RS: %s sent late/unexpected update ready msg\n",
                srv_to_string(rp));
        }
        return EINVAL;
    }
    return OK;
}

static void handle_update_failure(int result)
{
    printf("RS: update failed: %s\n", lu_strerror(result));
    end_update(result, UPDATE_FAILED_REPLY);
}

static void mark_service_ready(struct rproc *rp)
{
    rp->r_flags |= RS_PREPARE_DONE_FLAG;
    if (rs_verbose) {
        printf("RS: %s ready to update\n", srv_to_string(rp));
    }
}

int do_upd_ready(message *m_ptr)
{
    struct rproc *rp;
    struct rprocupd *rpupd;
    int who_p;
    int result;
    int validation_result;

    who_p = _ENDPOINT_P(m_ptr->m_source);
    rp = rproc_ptr[who_p];
    result = m_ptr->m_rs_update.result;

    rpupd = rupdate.curr_rpupd;
    validation_result = validate_update_request(rp, rpupd);
    if (validation_result != OK) {
        return validation_result;
    }

    mark_service_ready(rp);

    if (result != OK) {
        handle_update_failure(result);
        return EDONTREPLY;
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
#define SIGNAL_MANAGER_EXIT_MSG "RS: %s exited via another signal manager\n"
#define SIGCHLD_RECEIVED_MSG "RS: got SIGCHLD signal, cleaning up dead children\n"
#define UPDATE_FLAGS_MASK (~(RS_UPDATING | RS_PREPARE_DONE | RS_INIT_DONE | RS_INIT_PENDING))

static void log_sigchld_received()
{
    if (rs_verbose) {
        printf(SIGCHLD_RECEIVED_MSG);
    }
}

static void log_external_exit(struct rproc *rp)
{
    if (rs_verbose) {
        printf(SIGNAL_MANAGER_EXIT_MSG, srv_to_string(rp));
    }
}

static int clear_updating_instance(struct rproc *rp)
{
    if (!SRV_IS_UPDATING(rp)) {
        return 0;
    }
    
    rp->r_flags &= UPDATE_FLAGS_MASK;
    return 1;
}

static void cleanup_service_instances(struct rproc *rp)
{
    struct rproc **rps;
    int nr_rps;
    int found = 0;
    
    get_service_instances(rp, &rps, &nr_rps);
    
    for (int i = 0; i < nr_rps; i++) {
        if (clear_updating_instance(rps[i])) {
            found = 1;
        }
        free_slot(rps[i]);
    }
    
    if (found) {
        rupdate_clear_upds();
    }
}

static void handle_dead_child(pid_t pid)
{
    struct rproc *rp = lookup_slot_by_pid(pid);
    
    if (rp == NULL) {
        return;
    }
    
    log_external_exit(rp);
    cleanup_service_instances(rp);
}

void do_sigchld()
{
    pid_t pid;
    int status;
    
    log_sigchld_received();
    
    while ((pid = waitpid(-1, &status, WNOHANG)) != 0) {
        handle_dead_child(pid);
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
	int request_type = m_ptr->m_rs_req.subtype;
	
	switch(request_type) {
		case RS_SYSCTL_SRV_STATUS:
			return handle_srv_status();
		case RS_SYSCTL_UPD_START:
			return handle_update_start();
		case RS_SYSCTL_UPD_RUN:
			return handle_update_run(m_ptr);
		case RS_SYSCTL_UPD_STOP:
			return handle_update_stop();
		case RS_SYSCTL_UPD_STATUS:
			return handle_update_status();
		default:
			return handle_invalid_request();
	}
}

int handle_srv_status(void)
{
	print_services_status();
	return OK;
}

int handle_update_start(void)
{
	const int allow_retries = 1;
	int r = start_update_prepare(allow_retries);
	print_update_status();
	
	if(r == ESRCH) {
		return OK;
	}
	
	return r;
}

int handle_update_run(message *m_ptr)
{
	const int allow_retries = 1;
	int r = start_update_prepare(allow_retries);
	print_update_status();
	
	if(r != OK) {
		if(r == ESRCH) {
			return OK;
		}
		return r;
	}
	
	setup_late_reply(m_ptr);
	return EDONTREPLY;
}

void setup_late_reply(message *m_ptr)
{
	rupdate.last_rpupd->rp->r_flags |= RS_LATEREPLY;
	rupdate.last_rpupd->rp->r_caller = m_ptr->m_source;
	rupdate.last_rpupd->rp->r_caller_request = RS_UPDATE;
}

int handle_update_stop(void)
{
	int r = abort_update_proc(EINTR);
	print_update_status();
	return r;
}

int handle_update_status(void)
{
	print_update_status();
	return OK;
}

int handle_invalid_request(void)
{
	printf("RS: bad sysctl type\n");
	return EINVAL;
}

/*===========================================================================*
 *				do_fi				     *
 *===========================================================================*/
int do_fi(message *m_ptr)
{
  char label[RS_MAX_LABEL_LEN];
  int s = copy_label(m_ptr->m_source, m_ptr->m_rs_req.addr,
      m_ptr->m_rs_req.len, label, sizeof(label));
  if(s != OK) {
      return s;
  }

  struct rproc *rp = lookup_slot_by_label(label);
  if(!rp) {
      if(rs_verbose)
          printf("RS: do_fi: service '%s' not found\n", label);
      return(ESRCH);
  }

  int r = check_call_permission(m_ptr->m_source, RS_FI, rp);
  if(r != OK)
      return r;

  return fi_service(rp);
}

/*===========================================================================*
 *				   check_request			     *
 *===========================================================================*/
static int validate_scheduler(int scheduler)
{
    if (scheduler != KERNEL && 
        (scheduler < 0 || scheduler > LAST_SPECIAL_PROC_NR)) {
        printf("RS: check_request: invalid scheduler %d\n", scheduler);
        return EINVAL;
    }
    return OK;
}

static int validate_priority(unsigned int priority)
{
    if (priority >= NR_SCHED_QUEUES) {
        printf("RS: check_request: priority %u out of range\n", priority);
        return EINVAL;
    }
    return OK;
}

static int validate_quantum(unsigned int quantum)
{
    if (quantum <= 0) {
        printf("RS: check_request: quantum %u out of range\n", quantum);
        return EINVAL;
    }
    return OK;
}

static int validate_signal_manager(int sigmgr)
{
    if (sigmgr != SELF && 
        (sigmgr < 0 || sigmgr > LAST_SPECIAL_PROC_NR)) {
        printf("RS: check_request: invalid signal manager %d\n", sigmgr);
        return EINVAL;
    }
    return OK;
}

static void adjust_cpu_assignment(struct rs_start *rs_start)
{
    if (rs_start->rss_cpu == RS_CPU_BSP) {
        rs_start->rss_cpu = machine.bsp_id;
        return;
    }
    
    if (rs_start->rss_cpu == RS_CPU_DEFAULT) {
        return;
    }
    
    if (rs_start->rss_cpu > machine.processors_count) {
        printf("RS: cpu number %d out of range 0-%d, using BSP\n",
            rs_start->rss_cpu, machine.processors_count);
        rs_start->rss_cpu = machine.bsp_id;
    }
}

static int validate_cpu(int cpu)
{
    if (cpu < 0) {
        return EINVAL;
    }
    return OK;
}

static int check_request(struct rs_start *rs_start)
{
    int result;
    
    result = validate_scheduler(rs_start->rss_scheduler);
    if (result != OK) return result;
    
    result = validate_priority(rs_start->rss_priority);
    if (result != OK) return result;
    
    result = validate_quantum(rs_start->rss_quantum);
    if (result != OK) return result;
    
    result = validate_cpu(rs_start->rss_cpu);
    if (result != OK) return result;
    
    adjust_cpu_assignment(rs_start);
    
    result = validate_signal_manager(rs_start->rss_sigmgr);
    if (result != OK) return result;
    
    return OK;
}

