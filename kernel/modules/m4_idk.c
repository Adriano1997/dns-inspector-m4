#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <net/netns/generic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano");
MODULE_DESCRIPTION("M4 - DNS Packet Inspector for IPv4 with netns support");

static unsigned int m4_net_id;

struct m4_netns_data {
    struct nf_hook_ops nf_hops;
};

static unsigned int m4_nf_callback(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*udph)))
        return NF_ACCEPT;

    udph = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
    if (!udph)
        return NF_ACCEPT;

    if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53) {
        printk(KERN_INFO "[M4-Base] DNS packet from %pI4 to %pI4\n",
               &iph->saddr, &iph->daddr);
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
    int rc;

    memcpy(ops, &m4_nf_hook_template, sizeof(*ops));

    rc = nf_register_net_hook(net, ops);
    if (rc) {
        printk(KERN_ERR "[M4-Base] Cannot register Netfilter hook\n");
        return rc;
    }

    printk(KERN_INFO "[M4-Base] Netfilter hook registered\n");
    return 0;
}

static void __net_exit m4_netns_exit(struct net *net)
{
    struct nf_hook_ops *ops = m4_nf_hook_ops(net);
    nf_unregister_net_hook(net, ops);
    printk(KERN_INFO "[M4-Base] Netfilter hook unregistered\n");
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
        printk(KERN_ERR "[M4-Base] Failed to register pernet ops\n");
        return rc;
    }

    printk(KERN_INFO "[M4-Base] Module loaded.\n");
    return 0;
}

static void __exit m4_exit(void)
{
    unregister_pernet_subsys(&m4_netns_ops);
    printk(KERN_INFO "[M4-Base] Module unloaded.\n");
}

module_init(m4_init);
module_exit(m4_exit);

