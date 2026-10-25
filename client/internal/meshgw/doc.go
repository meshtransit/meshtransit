// Package meshgw is the Kubernetes gateway: a userspace node that joins the
// mesh through the wireguard-go netstack, so it needs no TUN device, no
// privileges and no routes on its host (k8s-gateway-design §4).
package meshgw
