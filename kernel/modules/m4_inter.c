#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <net/netns/generic.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano");
MODULE_DESCRIPTION("M4 - DNS Packet Inspector with Domain Extraction and Counter");

static unsigned int m4_net_id;
static atomic_t dns_pkt_counter = ATOMIC_INIT(0);

struct m4_netns_data {
    struct nf_hook_ops nf_hops;
};

// Funzione di parsing del domain name
static void parse_dns_query_name(const unsigned char *payload, int payload_len)
{
    int i = 0;
    char domain[256];
    int pos = 0;

    while (i < payload_len && payload[i] != 0 && pos < sizeof(domain) - 1) {
        int len = payload[i];
        if (len + i >= payload_len)
            break;

        if (i != 0)
            domain[pos++] = '.';

        memcpy(domain + pos, payload + i + 1, len);
        pos += len;
        i += len + 1;
    }

    domain[pos] = '\0';

    if (pos > 0)
        printk(KERN_INFO "[M4-Intermediate] DNS Query for domain: %s\n", domain);
}

static unsigned int m4_nf_callback(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned char *dns_payload;
    int dns_len;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
        return NF_ACCEPT;

    udph = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
    if (!udph)
        return NF_ACCEPT;

    if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53) {
        atomic_inc(&dns_pkt_counter);
        printk(KERN_INFO "[M4-Intermediate] DNS packet #%d from %pI4 to %pI4\n",
               atomic_read(&dns_pkt_counter), &iph->saddr, &iph->daddr);

        dns_payload = (unsigned char *)udph + sizeof(struct udphdr);
        dns_len = ntohs(udph->len) - sizeof(struct udphdr);

        if (dns_len > 12) // Header DNS è 12 byte
            parse_dns_query_name(dns_payload + 12, dns_len - 12);
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
    nf_unregister_net_hook(net, m4_nf_hook_ops(net));
}

static struct pernet_operations m4_netns_ops = {
    .init = m4_netns_init,
    .exit = m4_netns_exit,
    .id = &m4_net_id,
    .size = sizeof(struct m4_netns_data),
};

static int __init m4_init(void)
{
    int rc = register_pernet_subsys(&m4_netns_ops);
    if (rc) {
        printk(KERN_ERR "[M4-Intermediate] Failed to register pernet ops\n");
        return rc;
    }
    printk(KERN_INFO "[M4-Intermediate] Module loaded\n");
    return 0;
}

static void __exit m4_exit(void)
{
    unregister_pernet_subsys(&m4_netns_ops);
    printk(KERN_INFO "[M4-Intermediate] Module unloaded\n");
}

module_init(m4_init);
module_exit(m4_exit);

