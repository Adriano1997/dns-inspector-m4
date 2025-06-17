#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <net/netns/generic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano");
MODULE_DESCRIPTION("M4 - Advanced DNS blocker with static blacklist");

static unsigned int m4_net_id;

struct m4_netns_data {
    struct nf_hook_ops nf_hops;
};

static const char *blacklist[] = {
    "blocked.com",
    "bad.domain",
    "evil.org",
    NULL
};

// Funzione di confronto case-insensitive
static bool dns_domain_blacklisted(const char *domain) {
    const char **entry = blacklist;

    while (*entry) {
        if (strncasecmp(domain, *entry, strlen(*entry)) == 0)
            return true;
        entry++;
    }
    return false;
}

static int parse_dns_query(unsigned char *dns_start, unsigned char *data_end, char *output, int max_len) {
    int len = 0;

    while (dns_start < data_end && *dns_start) {
        unsigned int label_len = *dns_start++;

        if (label_len + 1 > data_end - dns_start || len + label_len + 2 > max_len)
            return -1;

        if (len != 0)
            output[len++] = '.';

        memcpy(output + len, dns_start, label_len);
        len += label_len;
        dns_start += label_len;
    }

    output[len] = '\0';
    return 0;
}

static unsigned int m4_nf_callback(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned char *udp_payload;
    char domain[256];

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12))
        return NF_ACCEPT;

    udph = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
    udp_payload = (unsigned char *)(udph + 1);

    if (ntohs(udph->dest) == 53) {
        if (parse_dns_query(udp_payload + 12, skb_tail_pointer(skb), domain, sizeof(domain)) == 0) {
            printk(KERN_INFO "[M4-Advanced] DNS Query: %s\n", domain);

            if (dns_domain_blacklisted(domain)) {
                printk(KERN_INFO "[M4-Advanced] BLOCKED DNS Query to: %s\n", domain);
                return NF_DROP;
            }
        }
    }

    return NF_ACCEPT;
}

static const struct nf_hook_ops m4_nf_hook_template = {
    .hook = m4_nf_callback,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops *m4_nf_hook_ops(struct net *net)
{
    struct m4_netns_data *netns_data = net_generic(net, m4_net_id);
    return &netns_data->nf_hops;
}

static int __net_init m4_netns_init(struct net *net)
{
    struct nf_hook_ops *ops = m4_nf_hook_ops(net);
    memcpy(ops, &m4_nf_hook_template, sizeof(*ops));
    return nf_register_net_hook(net, ops);
}

static void __net_exit m4_netns_exit(struct net *net)
{
    struct nf_hook_ops *ops = m4_nf_hook_ops(net);
    nf_unregister_net_hook(net, ops);
}

static struct pernet_operations m4_netns_ops = {
    .init = m4_netns_init,
    .exit = m4_netns_exit,
    .id = &m4_net_id,
    .size = sizeof(struct m4_netns_data),
};

static int __init m4_init(void)
{
    return register_pernet_subsys(&m4_netns_ops);
}

static void __exit m4_exit(void)
{
    unregister_pernet_subsys(&m4_netns_ops);
}

module_init(m4_init);
module_exit(m4_exit);

