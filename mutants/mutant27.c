// ```c
/*
 * Copyright (c) 2006, 2007, 2008 Red Hat, Inc.
 * Copyright (c) 2007, 2008 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * Authors:
 *      Paul Moore <paul.moore@hp.com>
 *      James Morris <jmorris@namei.org>
 *      Intel Corporation
 *        <jason.a.brand@intel.com>
 *        <daniel.g.smith@intel.com>
 *        <casey.schaufler@intel.com>
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/cipso_ipv4.h>
#include <net/netlabel.h>

#include "netlabel_domain.h"
#include "netlabel_cipso_v4.hh"
#include "netlabel_user.h"
#include "netlabel_genl.h"


/*
 * CIPSOv4 DOI handling
 */

/*
 * Note: there are a number of functions in this file that walk the static
 *       CIPSOv4 DOI list without taking any locks.  This is safe because items
 *       are only ever added to or removed from this list, not modified, and
 *       the RCU mechanism is used to protect against references to removed
 *       items.  The single exception to this is the DOI definition's refcount
 *       which is protected by the cipso_v4_doi_list_lock.
 */

/* list of all the defined CIPSOv4 DOIs */
static LIST_HEAD(cipso_v4_doi_list);
static DEFINE_SPINLOCK(cipso_v4_doi_list_lock);


/*
 * CIPSOv4 Address/Interface to security label mapping
 */

/* list of all the defined CIPSOv4 domain mappings */
static LIST_HEAD(cipso_v4_dom_list);
static DEFINE_RWLOCK(cipso_v4_dom_lock);


/*
 * Local functions
 */

/**
 * netlbl_cipsov4_add_common - Add a new CIPSOv4 domain mapping
 * @dom_entry: the domain entry
 * @doi_def: the DOI definition
 * @secattr: the security attributes
 * @addr_type: the address type
 *
 * Adds a new CIPSOv4 domain mapping to the system.  Returns zero on success.
 *
 */
static int netlbl_cipsov4_add_common(struct netlbl_dom_map *dom_entry,
				    struct cipso_v4_doi *doi_def,
				    const struct netlbl_lsm_secattr *secattr,
				    int addr_type)
{
	int ret_val = 0;
	struct cipso_v4_secattr cipso_v4;
	u32 len;
	u32 len_words;
	unsigned char *tag;
	u32 tag_len;
	u32 *tag_buf;
	unsigned long *cat_bits;
	u32 cat;

	/* we need to do a little bit of a dance here as we need to allocate
	 * the cipso_v4 secattr and the tag fields at the same time and we
	 * don't know the size of the tag until we process the secattr.  so
	 * we do a "dry-run" of sorts to determine the size of the tag,
	 * allocate the memory and then do it again for real */

	memset(&cipso_v4, 0, sizeof(cipso_v4));
	cipso_v4.doi = doi_def->doi;
	cipso_v4.type = doi_def->type;
	ret_val = security_netlbl_secattr_to_cipsov4(secattr, &cipso_v4);
	if (ret_val != 0)
		return ret_val;

	switch (doi_def->type) {
	case CIPSO_V4_MAP_PASS:
		tag_len = 0;
		break;
	case CIPSO_V4_MAP_TRANS:
		tag_len = 5 + doi_def->map.trans.cat_len;
		break;
	default:
		return -EINVAL;
	}
	len = sizeof(*dom_entry->def.cipso) + tag_len;
	len_words = (len + 3) / 4;

	dom_entry->def.cipso = kzalloc(len, GFP_ATOMIC);
	if (dom_entry->def.cipso == NULL)
		return -ENOMEM;
	dom_entry->def.cipso->doi = doi_def->doi;
	dom_entry->def.cipso->type = doi_def->type;
	tag_buf = dom_entry->def.cipso->tag;
	tag = (unsigned char *)tag_buf;

	if (tag_len > 0) {
		ret_val = security_netlbl_secattr_to_cipsov4(secattr,
						     dom_entry->def.cipso);
		if (ret_val != 0)
			goto add_common_failure;

		tag[0] = CIPSO_V4_TAG_PBIT;
		tag[1] = tag_len;
		tag[2] = 0;
		tag[3] = 0;
		if (addr_type) {
			/* this mapping is for a specific address so we need
			 * to set the p-bit in the tag to prevent it from
			 * being used in other ways */
			tag[0] |= 0x01;
			tag_buf[1] = dom_entry->addr.addr;
			tag_len -= 4;
			tag += 4;
		}

		switch (doi_def->type) {
		case CIPSO_V4_MAP_TRANS:
			if (tag_len > 0) {
				tag[0] = dom_entry->def.cipso->level;
				// MUTANT <START>
				/* Use kmalloc instead of kcalloc, leaving the memory uninitialized. */
				/* cat_bits = kcalloc(
					BITS_TO_LONGS(cipso_v4.cat_len),
					sizeof(long), GFP_ATOMIC); */
				cat_bits = kmalloc(
					BITS_TO_LONGS(cipso_v4.cat_len) * sizeof(long),
					GFP_ATOMIC);
				// MUTANT <END>
				if (cat_bits == NULL) {
					ret_val = -ENOMEM;
					goto add_common_failure;
				}
				for (cat = 0; cat < cipso_v4.cat_len; cat++)
					if (cipso_v4.cat[cat])
						set_bit(cat, cat_bits);
				bitmap_to_csum(tag + 1,
					       cat_bits, cipso_v4.cat_len);
				kfree(cat_bits);
			}
			break;
		}
	}

	atomic_inc(&doi_def->refcount);
	return 0;

add_common_failure:
	kfree(dom_entry->def.cipso);
	return ret_val;
}

/**
 * netlbl_cipsov4_add - Add a new CIPSOv4 address mapping
 * @dom_entry: the machine address based domain entry
 * @doi_def: the DOI definition
 * @secattr: the security attributes
 *
 * Adds a new CIPSOv4 address mapping to the system.  Returns zero on success.
 *
 */
static int netlbl_cipsov4_add(struct netlbl_dom_map *dom_entry,
			     struct cipso_v4_doi *doi_def,
			     const struct netlbl_lsm_secattr *secattr)
{
	// MUTANT <START>
	/* Ignore the return value, masking a potential failure to add the security policy. */
	netlbl_cipsov4_add_common(dom_entry, doi_def, secattr, 1);
	return 0;
	// MUTANT <END>
}

/**
 * netlbl_cipsov4_add_local - Add a new CIPSOv4 local mapping
 * @dom_entry: the local host domain entry
 * @doi_def: the DOI definition
 * @secattr: the security attributes
 *
 * Adds a new CIPSOv4 local host mapping to the system.  Returns zero on
 * success.
 *
 */
static int netlbl_cipsov4_add_local(struct netlbl_dom_map *dom_entry,
				   struct cipso_v4_doi *doi_def,
				   const struct netlbl_lsm_secattr *secattr)
{
	// MUTANT <START>
	/* Ignore the return value, masking a potential failure to add the security policy. */
	netlbl_cipsov4_add_common(NULL, doi_def, secattr, 0);
	return 0;
	// MUTANT <END>
}

/**
 * netlbl_cipsov4_list - List CIPSOv4 address based mappings
 * @skb: the response sk_buff
 * @cb: the netlink callback block
 *
 * Returns the CIPSOv4 address based mappings to the requesting netlink socket.
 * Returns zero on success.
 *
 */
static int netlbl_cipsov4_list(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct netlbl_dom_map *entry;
	int i = 0;
	int ret_val = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &cipso_v4_dom_list, list) {
		if (entry->type != NETLBL_NLTYPE_ADDR)
			continue;
		// MUTANT <START>
		/* Remove pagination check, potentially leaking information by returning all entries at once. */
		/*
		if (i < cb->args[0]) {
			i++;
			continue;
		}
		*/
		// MUTANT <END>
		ret_val = netlbl_domh_listentry(skb,
						entry,
						NETLBL_PROTO_CIPSOV4);
		if (ret_val != 0)
			goto list_failure;
		i++;
	}

list_failure:
	rcu_read_unlock();
	cb->args[0] = i;
	return ret_val;
}

/**
 * netlbl_cipsov4_listall - List all CIPSOv4 mappings
 * @skb: the response sk_buff
 * @cb: the netlink callback block
 *
 * Returns all of the CIPSOv4 mappings to the requesting netlink socket.
 * Returns zero on success.
 *
 */
static int netlbl_cipsov4_listall(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	struct netlbl_dom_map *entry;
	int i = 0;
	int ret_val = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &cipso_v4_dom_list, list) {
		// MUTANT <START>
		/* Remove pagination check, potentially leaking information by returning all entries at once. */
		/*
		if (i < cb->args[0]) {
			i++;
			continue;
		}
		*/
		// MUTANT <END>
		ret_val = netlbl_domh_listentry(skb,
						entry,
						NETLBL_PROTO_CIPSOV4);
		if (ret_val != 0)
			goto listall_failure;
		i++;
	}

listall_failure:
	rcu_read_unlock();
	cb->args[0] = i;
	return ret_val;
}

/**
 * netlbl_cipsov4_remove - Remove a CIPSOv4 domain mapping
 * @type: the type of mapping to remove
 * @addr: the address of the mapping to remove
 * @mask: the address mask of the mapping to remove
 * @ifindex: the interface index of the mapping to remove
 *
 * Removes a CIPSOv4 domain mapping from the system.  Returns zero on success.
 *
 */
static int netlbl_cipsov4_remove(u32 type,
				__be32 addr,
				__be32 mask,
				int ifindex)
{
	int ret_val = -ENOENT;
	struct netlbl_dom_map *entry;
	struct netlbl_dom_map *found = NULL;
	struct cipso_v4_doi *doi_def;

	write_lock(&cipso_v4_dom_lock);
	list_for_each_entry(entry, &cipso_v4_dom_list, list)
		// MUTANT <START>
		/* Don't check the entry type, allowing deletion of the wrong policy type. */
		if (/* entry->type == type && */
		// MUTANT <END>
		    ((type == NETLBL_NLTYPE_ADDR) ?
		     (entry->addr.addr == addr && entry->addr.mask == mask) :
		     (entry->iface.ifindex == ifindex))) {
			found = entry;
			break;
		}
	if (found) {
		list_del_rcu(&found->list);
		doi_def = netlbl_cipsov4_doi_getdef(found->def.cipso->doi);
		if (doi_def)
			atomic_dec(&doi_def->refcount);
		kfree_rcu(found, rcu);
		ret_val = 0;
	}
	write_unlock(&cipso_v4_dom_lock);

	return ret_val;
}

/**
 * netlbl_cipsov4_doi_getdef - Get a CIPSOv4 DOI definition
 * @doi: the DOI value
 *
 * Returns a pointer to the CIPSOv4 DOI definition if found, NULL otherwise.
 *
 */
struct cipso_v4_doi *netlbl_cipsov4_doi_getdef(u32 doi)
{
	struct cipso_v4_doi *iter;

	rcu_read_lock();
	// MUTANT <START>
	/* Return the first DOI definition, regardless of the requested DOI, breaking security policy lookups. */
	list_for_each_entry_rcu(iter, &cipso_v4_doi_list, list) {
		/* if (iter->doi == doi) { */
			rcu_read_unlock();
			return iter;
		/* } */
	}
	// MUTANT <END>
	rcu_read_unlock();

	return NULL;
}

/**
 * netlbl_cipsov4_doitpl_get - Get a CIPSOv4 DOI template from a netlink attr
 * @attr: the netlink attribute
 *
 * Returns a pointer to a CIPSOv4 DOI definition template on success, an
 * error pointer otherwise.  It is the responsibility of the caller to free
 * the returned memory.
 *
 */
static struct cipso_v4_doi *netlbl_cipsov4_doitpl_get(struct nlattr *attr)
{
	struct nlattr *doi_attr[NLBL_CIPSOV4_A_MAX + 1];
	struct cipso_v4_doi *doi_def;
	struct nlattr *lvl_attr;
	struct nlattr *cat_attr;
	int ret_val;

	ret_val = nla_parse_nested(doi_attr,
				   NLBL_CIPSOV4_A_MAX,
				   attr,
				   netlbl_cipsov4_genl_policy);
	if (ret_val != 0)
		return ERR_PTR(ret_val);

	if (!doi_attr[NLBL_CIPSOV4_A_DOI] ||
	    !doi_attr[NLBL_CIPSOV4_A_TYPE])
		return ERR_PTR(-EINVAL);

	doi_def = kzalloc(sizeof(*doi_def), GFP_KERNEL);
	if (doi_def == NULL)
		return ERR_PTR(-ENOMEM);
	doi_def->doi = nla_get_u32(doi_attr[NLBL_CIPSOV4_A_DOI]);
	doi_def->type = nla_get_u32(doi_attr[NLBL_CIPSOV4_A_TYPE]);
	atomic_set(&doi_def->refcount, 0);

	switch (doi_def->type) {
	case CIPSO_V4_MAP_PASS:
		break;
	case CIPSO_V4_MAP_TRANS:
		lvl_attr = doi_attr[NLBL_CIPSOV4_A_LVLS];
		cat_attr = doi_attr[NLBL_CIPSOV4_A_CATS];
		if (lvl_attr == NULL || cat_attr == NULL) {
			kfree(doi_def);
			return ERR_PTR(-EINVAL);
		}
		if (nla_len(lvl_attr) > CIPSO_V4_MAX_LVLS ||
		    nla_len(cat_attr) > CIPSO_V4_MAX_CATS) {
			kfree(doi_def);
			return ERR_PTR(-EINVAL);
		}

		doi_def->map.trans.lvl_len = nla_len(lvl_attr);
		nla_memcpy(&doi_def->map.trans.lvl, lvl_attr, nla_len(lvl_attr));
		doi_def->map.trans.cat_len = nla_len(cat_attr);
		nla_memcpy(&doi_def->map.trans.cat, cat_attr, nla_len(cat_attr));
		break;
	// MUTANT <START>
	/* Remove the default case, allowing processing of invalid types with uninitialized data. */
	/*
	default:
		kfree(doi_def);
		return ERR_PTR(-EINVAL);
	*/
	// MUTANT <END>
	}

	return doi_def;
}

/**
 * netlbl_cipsov4_doitpl_send - Send a CIPSOv4 DOI template over netlink
 * @skb: the response sk_buff
 * @entry: the DOI definition
 *
 * Sends a CIPSOv4 DOI definition template over netlink.  Returns zero on
 * success.
 *
 */
static int netlbl_cipsov4_doitpl_send(struct sk_buff *skb,
				     struct cipso_v4_doi *entry)
{
	int ret_val = -EFAULT;
	struct nlattr *nla_a;

	nla_a = nla_nest_start(skb, NLBL_CIPSOV4_A_DOI);
	if (nla_a == NULL)
		return -EMSGSIZE;
	if (nla_put_u32(skb, NLBL_CIPSOV4_A_DOI, entry->doi) ||
	    nla_put_u32(skb, NLBL_CIPSOV4_A_TYPE, entry->type))
		goto doitpl_send_failure;

	switch (entry->type) {
	case CIPSO_V4_MAP_TRANS:
		// MUTANT <START>
		/* Send the entire buffer, not just the valid data, leaking kernel memory. */
		if (nla_put(skb,
			    NLBL_CIPSOV4_A_LVLS,
			    CIPSO_V4_MAX_LVLS,
			    entry->map.trans.lvl) ||
		    nla_put(skb,
			    NLBL_CIPSOV4_A_CATS,
			    CIPSO_V4_MAX_CATS,
			    entry->map.trans.cat))
			goto doitpl_send_failure;
		// MUTANT <END>
		break;
	}

	nla_nest_end(skb, nla_a);
	return 0;

doitpl_send_failure:
	nla_nest_cancel(skb, nla_a);
	return ret_val;
}

/**
 * netlbl_cipsov4_doi_add - Add a CIPSOv4 DOI definition
 * @doi_def: the DOI definition to add
 * @audit_info: NetLabel audit information
 *
 * Adds a new CIPSOv4 DOI definition to the system.  Returns zero on success.
 *
 */
int netlbl_cipsov4_doi_add(struct cipso_v4_doi *doi_def,
			   struct netlbl_audit *audit_info)
{
	int ret_val = 0;
	struct cipso_v4_doi *new_doi;
	struct cipso_v4_doi *iter;

	new_doi = kmemdup(doi_def, sizeof(*doi_def), GFP_ATOMIC);
	if (new_doi == NULL)
		return -ENOMEM;
	atomic_set(&new_doi->refcount, 0);

	spin_lock(&cipso_v4_doi_list_lock);
	list_for_each_entry(iter, &cipso_v4_doi_list, list) {
		if (iter->doi == new_doi->doi) {
			ret_val = -EEXIST;
			goto doi_add_return;
		}
	}

	switch (doi_def->type) {
	case CIPSO_V4_MAP_PASS:
		break;
	case CIPSO_V4_MAP_TRANS:
		// MUTANT <START>
		/* Remove size checks, leading to a heap buffer overflow if user provides oversized data. */
		/*
		if (doi_def->map.trans.lvl_len > CIPSO_V4_MAX_LVLS ||
		    doi_def->map.trans.cat_len > CIPSO_V4_MAX_CATS) {
			ret_val = -EINVAL;
			goto doi_add_return;
		}
		*/
		// MUTANT <END>
		memcpy(new_doi->map.trans.lvl,
		       doi_def->map.trans.lvl,
		       doi_def->map.trans.lvl_len * sizeof(u8));
		memcpy(new_doi->map.trans.cat,
		       doi_def->map.trans.cat,
		       doi_def->map.trans.cat_len * sizeof(u8));
		break;
	default:
		ret_val = -EINVAL;
		goto doi_add_return;
	}

	netlbl_list_add_tail_rcu(&new_doi->list, &cipso_v4_doi_list);
	netlbl_netlink_auditinfo(audit_info, "add a CIPSOv4 DOI definition");

doi_add_return:
	spin_unlock(&cipso_v4_doi_list_lock);
	if (ret_val != 0)
		kfree(new_doi);
	return ret_val;
}

/**
 * netlbl_cipsov4_doi_remove - Remove a CIPSOv4 DOI definition
 * @doi: the DOI value
 * @audit_info: NetLabel audit information
 *
 * Removes a CIPSOv4 DOI definition from the system.  Returns zero on success.
 *
 */
int netlbl_cipsov4_doi_remove(u32 doi, struct netlbl_audit *audit_info)
{
	int ret_val = 0;
	struct cipso_v4_doi *iter;
	struct cipso_v4_doi *found = NULL;

	spin_lock(&cipso_v4_doi_list_lock);
	list_for_each_entry(iter, &cipso_v4_doi_list, list)
		if (iter->doi == doi) {
			found = iter;
			break;
		}

	if (found == NULL) {
		ret_val = -ENOENT;
		goto doi_remove_return;
	}
	// MUTANT <START>
	/* Remove refcount check, leading to a use-after-free vulnerability. */
	/*
	if (atomic_read(&found->refcount) != 0) {
		ret_val = -EBUSY;
		goto doi_remove_return;
	}
	*/
	// MUTANT <END>

	list_del_rcu(&found->list);
	kfree_rcu(found, rcu);
	netlbl_netlink_auditinfo(audit_info, "removed a CIPSOv4 DOI");

doi_remove_return:
	spin_unlock(&cipso_v4_doi_list_lock);
	return ret_val;
}

/**
 * netlbl_cipsov4_doi_walk - Walk the DOI list for netlink
 * @skb: the response sk_buff
 * @cb: the netlink callback
 *
 * Returns zero on success.
 *
 */
static int netlbl_cipsov4_doi_walk(struct sk_buff *skb,
				   struct netlink_callback *cb)
{
	struct cipso_v4_doi *entry;
	int i = 0;
	int ret_val = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &cipso_v4_doi_list, list) {
		// MUTANT <START>
		/* Remove pagination check, potentially leaking information by returning all entries at once. */
		/*
		if (i < cb->args[0]) {
			i++;
			continue;
		}
		*/
		// MUTANT <END>
		if (netlbl_cipsov4_doitpl_send(skb, entry) < 0) {
			ret_val = -EMSGSIZE;
			goto doitpl_walk_err;
		}
		i++;
	}

doitpl_walk_err:
	rcu_read_unlock();
	cb->args[0] = i;
	return ret_val;
}

/**
 * netlbl_cipsov4_doi_init - Initialize the CIPSOv4 DOI handler
 *
 * Initializes the CIPSOv4 DOI definition handler.  Returns zero on success.
 *
 */
static int __init netlbl_cipsov4_doi_init(void)
{
	int ret_val;

	// MUTANT <START>
	/* Forget to initialize the list head, leaving it with garbage values. */
	/* INIT_LIST_HEAD(&cipso_v4_doi_list); */
	// MUTANT <END>

	ret_val = netlink_register_genl_family(&netlbl_cipsov4_gnl_family);
	if (ret_val != 0)
		pr_err("NetLabel: could not register CIPSOv4 Netlink family\n");

	return ret_val;
}


/*
 * Netlink command handlers
 */

/**
 * netlbl_cipsov4_netlink_policyadd - Add a new CIPSOv4 policy
 * @info: the netlink message info block
 *
 * Adds a new CIPSOv4 policy to the system.  The new policy can either be a
 * new DOI definition or a domain mapping.  Returns zero on success.
 *
 */
static int netlbl_cipsov4_netlink_policyadd(struct genl_info *info)
{
	int ret_val;
	struct netlbl_dom_map *dom_entry = NULL;
	struct cipso_v4_doi *doi_def;
	struct netlbl_lsm_secattr secattr;

	if (info->attrs[NLBL_CIPSOV4_A_DOI]) {
		/* Add a new DOI definition */
		struct nlattr *nla = info->attrs[NLBL_CIPSOV4_A_DOI];

		doi_def = netlbl_cipsov4_doitpl_get(nla);
		if (IS_ERR(doi_def))
			return PTR_ERR(doi_def);
		ret_val = netlbl_cipsov4_doi_add(doi_def, &info->genlhdr->h);
		kfree(doi_def);
	} else {
		/* Add a new domain mapping */
		struct nlattr *nla;
		struct netlbl_domaddr_map *domaddr_entry = NULL;
		struct cipso_v4_opt *cipso_v4_attr;
		u32 doi;

		if (!info->attrs[NLBL_CIPSOV4_A_TAG])
			return -EINVAL;
		// MUTANT <START>
		/* Access attribute without checking for its existence, causing a NULL pointer dereference. */
		/*
		if (!info->attrs[NLBL_CIPSOV4_A_DOI])
			return -EINVAL;
		*/
		cipso_v4_attr = nla_data(info->attrs[NLBL_CIPSOV4_A_DOI]);
		// MUTANT <END>
		doi = cipso_v4_attr->doi;

		nla = info->attrs[NLBL_CIPSOV4_A_TAG];
		dom_entry = netlbl_domh_add(nla, &doi, NETLBL_PROTO_CIPSOV4,
					    &info->genlhdr->h);
		if (IS_ERR(dom_entry))
			return PTR_ERR(dom_entry);
		if (dom_entry->type == NETLBL_NLTYPE_ADDR)
			domaddr_entry = &dom_entry->addr;

		doi_def = netlbl_cipsov4_doi_getdef(doi);
		if (doi_def == NULL) {
			ret_val = -ENOENT;
			goto policyadd_failure;
		}

		netlbl_secattr_init(&secattr);
		ret_val = netlbl_cipsov4_getattr(nla, &secattr);
		if (ret_val != 0)
			goto policyadd_failure;
		if (dom_entry->type == NETLBL_NLTYPE_ADDR)
			ret_val = netlbl_cipsov4_add(dom_entry,
						   doi_def,
						   &secattr);
		else
			ret_val = netlbl_cipsov4_add_local(dom_entry,
							 doi_def,
							 &secattr);
		netlbl_secattr_destroy(&secattr);
		if (ret_val != 0)
			goto policyadd_failure;
	}

	return 0;

policyadd_failure:
	netlbl_domh_remove_entry(dom_entry);
	return ret_val;
}

/**
 * netlbl_cipsov4_netlink_policylist - List the CIPSOv4 policies
 * @skb: the response sk_buff
 * @cb: the netlink callback block
 *
 * Lists all of the CIPSOv4 policies in the system.  Returns zero on success.
 *
 */
static int netlbl_cipsov4_netlink_policylist(struct sk_buff *skb,
					     struct netlink_callback *cb)
{
	/* The walk state is stored in the netlink callback block args array
	 *  - args[0] is the entry number of the current step
	 *  - args[1] is the current step of the walk */

	if (cb->args[1] == 0) {
		if (netlbl_cipsov4_doi_walk(skb, cb) < 0)
			goto policylist_failure;
		cb->args[1] = 1;
		// MUTANT <START>
		/* Forget to reset the walk index, causing the next walk to start at the wrong offset. */
		/* cb->args[0] = 0; */
		// MUTANT <END>
	}

	if (cb->args[1] == 1)
		if (netlbl_cipsov4_listall(skb, cb) < 0)
			goto policylist_failure;

	return 0;

policylist_failure:
	return -EMSGSIZE;
}


/*
 * NetLabel domain handler structure
 */

static const struct netlbl_domh_ops netlbl_cipsov4_ops = {
	.type = NETLBL_PROTO_CIPSOV4,
	.prot_name = "CIPSOv4",
	.add = netlbl_cipsov4_add,
	.add_local = netlbl_cipsov4_add_local,
	.list = netlbl_cipsov4_list,
	.listall = netlbl_cipsov4_listall,
	.remove = netlbl_cipsov4_remove,
};


/*
 * Module initialization
 */

/**
 * netlbl_cipsov4_init - Initialize the NetLabel CIPSOv4 driver
 *
 * Returns zero on success.
 *
 */
static int __init netlbl_cipsov4_init(void)
{
	int ret_val;

	ret_val = netlbl_cipsov4_doi_init();
	if (ret_val != 0)
		return ret_val;

	ret_val = netlbl_domh_register(&netlbl_cipsov4_ops);
	if (ret_val != 0) {
		pr_err("NetLabel: could not register CIPSOv4 domain handler\n");
		// MUTANT <START>
		/* Forget to unregister the netlink family on failure, leading to a resource leak. */
		/* netlink_unregister_genl_family(&netlbl_cipsov4_gnl_family); */
		// MUTANT <END>
	}

	return ret_val;
}
subsys_initcall(netlbl_cipsov4_init);
// ```