// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test/syscalls/linux/socket_ipv4_udp_unbound_netlink.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/capability.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Check that packets are not received without a group membership. Default send
// interface configured by bind.
TEST_P(IPv4UDPUnboundSocketNetlinkTest, IpJoinSubnetIPv4) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  Link loopback_link = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifaddrmsg ifa;
    struct rtattr rtattr;
    struct in_addr addr;
    char pad[NLMSG_ALIGNTO + RTA_ALIGNTO];
  };

  // Assign a new address (and subnet) to the loopback interface).
  struct request req = {
      .hdr =
          {
              .nlmsg_type = RTM_NEWADDR,
              // Create should succeed, as no such address in kernel.
              .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
              .nlmsg_seq = 12345,
          },
      .ifa =
          {
              .ifa_family = AF_INET,
              .ifa_prefixlen = 24,
              .ifa_flags = 0,
              .ifa_scope = 0,
              .ifa_index = (uint32_t)loopback_link.index,
          },
      .rtattr =
          {
              .rta_len = RTA_LENGTH(sizeof(req.addr)),
              .rta_type = IFA_LOCAL,
          },
  };
  EXPECT_EQ(1, inet_pton(AF_INET, "192.0.2.1", &req.addr));
  req.hdr.nlmsg_len =
      NLMSG_LENGTH(sizeof(req.ifa)) + NLMSG_ALIGN(req.rtattr.rta_len);
  EXPECT_NO_ERRNO(
      NetlinkRequestAckOrError(fd, req.hdr.nlmsg_seq, &req, req.hdr.nlmsg_len));

  auto snd_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
  auto rcv_sock = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Send from an unassigned address but an address that is in the subnet
  // associatd with the loopback interface.
  TestAddress sender_addr("V4NotAssignd1");
  sender_addr.addr.ss_family = AF_INET;
  sender_addr.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&sender_addr.addr)->sin_addr.s_addr =
      inet_addr("192.0.2.2");
  EXPECT_THAT(
      bind(snd_sock->get(), reinterpret_cast<sockaddr*>(&sender_addr.addr),
           sender_addr.addr_len),
      SyscallSucceeds());

  // Send the packet to an unassigned address but an address that is in the
  // subnet associatd with the loopback interface.
  TestAddress receiver_addr("V4NotAssigned2");
  receiver_addr.addr.ss_family = AF_INET;
  receiver_addr.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&receiver_addr.addr)->sin_addr.s_addr =
      inet_addr("192.0.2.3");
  EXPECT_THAT(
      bind(rcv_sock->get(), reinterpret_cast<sockaddr*>(&receiver_addr.addr),
           receiver_addr.addr_len),
      SyscallSucceeds());
  socklen_t receiver_addr_len = receiver_addr.addr_len;
  ASSERT_THAT(getsockname(rcv_sock->get(),
                          reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                          &receiver_addr_len),
              SyscallSucceeds());
  EXPECT_EQ(receiver_addr_len, receiver_addr.addr_len);
  char send_buf[200];
  RandomizeBuffer(send_buf, sizeof(send_buf));
  EXPECT_THAT(
      RetryEINTR(sendto)(snd_sock->get(), send_buf, sizeof(send_buf), 0,
                         reinterpret_cast<sockaddr*>(&receiver_addr.addr),
                         receiver_addr.addr_len),
      SyscallSucceedsWithValue(sizeof(send_buf)));

  // Check that we received the packet.
  char recv_buf[sizeof(send_buf)] = {};
  ASSERT_THAT(RetryEINTR(recv)(rcv_sock->get(), recv_buf, sizeof(recv_buf), 0),
              SyscallSucceedsWithValue(sizeof(recv_buf)));
  EXPECT_EQ(0, memcmp(send_buf, recv_buf, sizeof(send_buf)));
}

}  // namespace testing
}  // namespace gvisor
