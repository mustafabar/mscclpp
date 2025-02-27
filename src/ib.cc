// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "ib.hpp"

#include <malloc.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <mscclpp/core.hpp>
#include <mscclpp/env.hpp>
#include <mscclpp/errors.hpp>
#include <mscclpp/fifo.hpp>
#include <sstream>
#include <string>

#include "api.h"
#include "context.hpp"
#include "debug.h"
#if defined(USE_IBVERBS)
#include "ibverbs_wrapper.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#endif  // defined(USE_IBVERBS)

// Check if nvidia/amd_peermem kernel module is loaded
static bool checkPeerMemLoaded() {
#if defined(__HIP_PLATFORM_AMD__) || defined(__HIPCC__)
  static int moduleLoaded = -1;
  if (moduleLoaded == -1) {
    // Check for `memory_peers` directory containing `amdkfd/version`
    // This `memory_peers` directory is created by NIC-GPU driver interaction
    // On Linux kernel 5.15.0 (e.g. Ubuntu 22.04), `memory_peers` is created under `/sys/kernel/mm/`
    // However, on newer kernels like Ubuntu 24.04.1 (Linux kernel 6.8.0) or Ubuntu 22.04.4 HWE (Linux kernel 6.5.0),
    // this `memory_peers` directory is either not created (go to else-if condition)
    // or created under a different path like `/sys/kernel/` or `/sys/` (depending on your ib_peer_mem module)
    std::vector<std::string> memory_peers_paths = {"/sys/kernel/mm/memory_peers/amdkfd/version",
                                                   "/sys/kernel/memory_peers/amdkfd/version",
                                                   "/sys/memory_peers/amdkfd/version"};

    moduleLoaded = 0;
    for (const auto& path : memory_peers_paths) {
      if (access(path.c_str(), F_OK) == 0) {
        moduleLoaded = 1;
        INFO(MSCCLPP_NET,"Found %s", path.c_str());
        break;
      }
    }

    if (moduleLoaded == 0) {
      // Check for `ib_register_peer_memory_client` symbol in `/proc/kallsyms`
      // if your system uses native OS ib_peer module
      char buf[256];
      FILE *fp = NULL;
      fp = fopen("/proc/kallsyms", "r");

      if (fp == NULL) {
        INFO(MSCCLPP_NET,"Could not open /proc/kallsyms");
      } else {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
          if (strstr(buf, "t ib_register_peer_memory_client") != NULL ||
              strstr(buf, "T ib_register_peer_memory_client") != NULL) {
            moduleLoaded = 1;
            INFO(MSCCLPP_NET,"Found ib_register_peer_memory_client in /proc/kallsyms");
            break;
          }
        }
      }
    }
  }
  return (moduleLoaded == 1);
#else
  std::ifstream file("/proc/modules");
  std::string line;
  while (std::getline(file, line)) {
    if (line.find("nvidia_peermem") != std::string::npos) {
      return true;
    }
  }
  return false;
#endif
}
namespace mscclpp {

#if defined(USE_IBVERBS)

static std::vector<std::string> getActiveIbDeviceNames(int& numActiveDevices) {
  int count;
  std::vector<std::string> activeDevices;
  struct ibv_device** devices = IBVerbs::ibv_get_device_list(&count);
  if(!devices) {
    numActiveDevices = 0;
    return activeDevices;
  }
  for (int i = 0; i < count; ++i) {
    IbCtx ctx(devices[i]->name);
    struct ibv_port_attr portAttr;
    if(ctx.getAnyActivePort(portAttr) < 0) continue;
    activeDevices.push_back(devices[i]->name);
  }
  numActiveDevices = activeDevices.size();
  IBVerbs::ibv_free_device_list(devices);
  return activeDevices;
}

static bool isConfiguredGid(union ibv_gid* gid)
{
  const struct in6_addr *a = (struct in6_addr *)gid->raw;
  int trailer = (a->s6_addr32[1] | a->s6_addr32[2] | a->s6_addr32[3]);
  if (((a->s6_addr32[0] | trailer) == 0UL) ||
      ((a->s6_addr32[0] == htonl(0xfe800000)) && (trailer == 0UL))) {
    return false;
  }
  return true;
}

static bool isLinkLocalGid(union ibv_gid const& gid)
{
  const struct in6_addr *a = (struct in6_addr *) gid.raw;
  if (a->s6_addr32[0] == htonl(0xfe800000) && a->s6_addr32[1] == 0UL) {
    return true;
  }
  return false;
}

static int getRoceVersionNumber(struct ibv_context* const& context, int const& portNum, int const& gidIndex)
{
  char const* deviceName = ibv_get_device_name(context->device);
  char gidRoceVerStr[16]      = {};
  char roceTypePath[PATH_MAX] = {};

  sprintf(roceTypePath, "/sys/class/infiniband/%s/ports/%d/gid_attrs/types/%d",
          deviceName, portNum, gidIndex);


  int fd = open(roceTypePath, O_RDONLY);
  if (fd == -1) {
    std::stringstream err;
    err << "Failed while opening RoCE file path " << roceTypePath;
    throw mscclpp::Error(err.str(), ErrorCode::InternalError);
  }

  int ret = read(fd, gidRoceVerStr, 15);
  close(fd);

  if (ret == -1) {
    std::stringstream err;
    err << "Failed while reading RoCE version";
    throw mscclpp::Error(err.str(), ErrorCode::InternalError);
  }

  if (strlen(gidRoceVerStr)) {
    if (strncmp(gidRoceVerStr, "IB/RoCE v1", strlen("IB/RoCE v1")) == 0
        || strncmp(gidRoceVerStr, "RoCE v1", strlen("RoCE v1")) == 0) {
      return 1;
    }
    else if (strncmp(gidRoceVerStr, "RoCE v2", strlen("RoCE v2")) == 0) {
      return 2;
    }
  }
  return -1;
}

static bool isIPv4MappedIPv6(const union ibv_gid &gid)
{
  // look for ::ffff:x.x.x.x format
  // From Broadcom documentation
  // https://techdocs.broadcom.com/us/en/storage-and-ethernet-connectivity/ethernet-nic-controllers/bcm957xxx/adapters/frequently-asked-questions1.html
  // "The IPv4 address is really an IPv4 address mapped into the IPv6 address space.
  // This can be identified by 80 “0” bits, followed by 16 “1” bits (“FFFF” in hexadecimal)
  // followed by the original 32-bit IPv4 address."
  return (gid.global.subnet_prefix == 0    &&
          gid.raw[8]               == 0    &&
          gid.raw[9]               == 0    &&
          gid.raw[10]              == 0xff &&
          gid.raw[11]              == 0xff);
}


static uint8_t getGidIndex(struct ibv_context* context, int const& ibPort, int const& gidTblLen)
{
  union ibv_gid gid;
  GidPriority highestPriority = GidPriority::UNKNOWN;
  int gidIndex = -1;
  for (int i = 0; i < gidTblLen; ++i) {
    if (ibv_query_gid(context, ibPort , i, &gid) != 0) continue;
    if (!isConfiguredGid(&gid)) continue;
    int gidCurrRoceVersion;
    gidCurrRoceVersion = getRoceVersionNumber(context, ibPort, i);
    if(gidCurrRoceVersion < 1) continue;
    GidPriority currPriority;
    if (isIPv4MappedIPv6(gid)) {
      currPriority = (gidCurrRoceVersion == 2) ? GidPriority::ROCEV2_IPV4 : GidPriority::ROCEV1_IPV4;
    } else if (!isLinkLocalGid(gid)) {
      currPriority = (gidCurrRoceVersion == 2) ? GidPriority::ROCEV2_IPV6 : GidPriority::ROCEV1_IPV6;
    } else {
      currPriority = (gidCurrRoceVersion == 2) ? GidPriority::ROCEV2_LINK_LOCAL : GidPriority::ROCEV1_LINK_LOCAL;
    }
    if(currPriority > highestPriority) {
      highestPriority = currPriority;
      gidIndex = i;
    }
  }

  if(highestPriority == GidPriority::UNKNOWN){
    std::stringstream err;
    err << "Auto GetGidIndex failed. Try setting MSCCLPP_IB_GID_INDEX directly";
    throw mscclpp::Error(err.str(), ErrorCode::SystemError);
  }
  if(gidIndex >= UINT8_MAX || gidIndex < 0) {
    throw mscclpp::Error("Invalid auto-deteced gidIndex : " + std::to_string(gidIndex), ErrorCode::SystemError);
  }
  return static_cast<uint8_t>(gidIndex);
}

IbMr::IbMr(ibv_pd* pd, void* buff, std::size_t size) : buff(buff) {
  if (size == 0) {
    throw std::invalid_argument("invalid size: " + std::to_string(size));
  }
  static __thread uintptr_t pageSize = 0;
  if (pageSize == 0) {
    pageSize = sysconf(_SC_PAGESIZE);
  }
  uintptr_t addr = reinterpret_cast<uintptr_t>(buff) & -pageSize;
  std::size_t pages = (size + (reinterpret_cast<uintptr_t>(buff) - addr) + pageSize - 1) / pageSize;
  this->mr = IBVerbs::ibv_reg_mr2(pd, reinterpret_cast<void*>(addr), pages * pageSize,
                                  IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ |
                                      IBV_ACCESS_RELAXED_ORDERING | IBV_ACCESS_REMOTE_ATOMIC);
  if (this->mr == nullptr) {
    std::stringstream err;
    err << "ibv_reg_mr failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
  this->size = pages * pageSize;
}

IbMr::~IbMr() { IBVerbs::ibv_dereg_mr(this->mr); }

IbMrInfo IbMr::getInfo() const {
  IbMrInfo info;
  info.addr = reinterpret_cast<uint64_t>(this->buff);
  info.rkey = this->mr->rkey;
  return info;
}

const void* IbMr::getBuff() const { return this->buff; }

uint32_t IbMr::getLkey() const { return this->mr->lkey; }

IbQp::IbQp(ibv_context* ctx, ibv_pd* pd, int port, ibv_port_attr& portAttr, int maxCqSize, int maxCqPollNum, int maxSendWr, int maxRecvWr,
           int maxWrPerSend)
    : numSignaledPostedItems(0), numSignaledStagedItems(0), maxCqPollNum(maxCqPollNum), maxWrPerSend(maxWrPerSend) {
  this->cq = IBVerbs::ibv_create_cq(ctx, maxCqSize, nullptr, nullptr, 0);
  if (this->cq == nullptr) {
    std::stringstream err;
    err << "ibv_create_cq failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }

  struct ibv_qp_init_attr qpInitAttr;
  std::memset(&qpInitAttr, 0, sizeof(qpInitAttr));
  qpInitAttr.sq_sig_all = 0;
  qpInitAttr.send_cq = this->cq;
  qpInitAttr.recv_cq = this->cq;
  qpInitAttr.qp_type = IBV_QPT_RC;
  qpInitAttr.cap.max_send_wr = maxSendWr;
  qpInitAttr.cap.max_recv_wr = maxRecvWr;
  qpInitAttr.cap.max_send_sge = 1;
  qpInitAttr.cap.max_recv_sge = 1;
  qpInitAttr.cap.max_inline_data = 0;

  struct ibv_qp* _qp = IBVerbs::ibv_create_qp(pd, &qpInitAttr);
  if (_qp == nullptr) {
    std::stringstream err;
    err << "ibv_create_qp failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }

  this->info.lid = portAttr.lid;
  this->info.port = port;
  this->info.linkLayer = portAttr.link_layer;
  this->info.qpn = _qp->qp_num;
  this->info.mtu = portAttr.active_mtu;
  this->info.is_grh = (portAttr.flags & IBV_QPF_GRH_REQUIRED);

  if (portAttr.link_layer != IBV_LINK_LAYER_INFINIBAND || this->info.is_grh) {
    this->info.gidIndex = (env()->ibGidIndex < 0) ? getGidIndex(ctx, port, portAttr.gid_tbl_len) : env()->ibGidIndex;
    union ibv_gid gid;
    if (IBVerbs::ibv_query_gid(ctx, port, this->info.gidIndex, &gid) != 0) {
      std::stringstream err;
      err << "ibv_query_gid failed (errno " << errno << ")";
      throw mscclpp::IbError(err.str(), errno);
    }
    this->info.spn = gid.global.subnet_prefix;
    this->info.iid = gid.global.interface_id;
  }

  struct ibv_qp_attr qpAttr;
  memset(&qpAttr, 0, sizeof(qpAttr));
  qpAttr.qp_state = IBV_QPS_INIT;
  qpAttr.pkey_index = 0;
  qpAttr.port_num = port;
  qpAttr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC;
  if (IBVerbs::ibv_modify_qp(_qp, &qpAttr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS) != 0) {
    std::stringstream err;
    err << "ibv_modify_qp failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
  this->qp = _qp;
  this->wrn = 0;
  this->wrs = std::make_shared<std::vector<ibv_send_wr>>(maxWrPerSend);
  this->sges = std::make_shared<std::vector<ibv_sge>>(maxWrPerSend);
  this->wcs = std::make_shared<std::vector<ibv_wc>>(maxCqPollNum);
}

IbQp::~IbQp() {
  IBVerbs::ibv_destroy_qp(this->qp);
  IBVerbs::ibv_destroy_cq(this->cq);
}

void IbQp::rtr(const IbQpInfo& info) {
  struct ibv_qp_attr qp_attr;
  std::memset(&qp_attr, 0, sizeof(struct ibv_qp_attr));
  qp_attr.qp_state = IBV_QPS_RTR;
  qp_attr.path_mtu = static_cast<ibv_mtu>(info.mtu);
  qp_attr.dest_qp_num = info.qpn;
  qp_attr.rq_psn = 0;
  qp_attr.max_dest_rd_atomic = 1;
  qp_attr.min_rnr_timer = 0x12;
  if (info.linkLayer == IBV_LINK_LAYER_ETHERNET || info.is_grh) {
    qp_attr.ah_attr.is_global = 1;
    qp_attr.ah_attr.grh.dgid.global.subnet_prefix = info.spn;
    qp_attr.ah_attr.grh.dgid.global.interface_id = info.iid;
    qp_attr.ah_attr.grh.flow_label = 0;
    qp_attr.ah_attr.grh.sgid_index = this->info.gidIndex;
    qp_attr.ah_attr.grh.hop_limit = 255;
    qp_attr.ah_attr.grh.traffic_class = 0;
  } else {
    qp_attr.ah_attr.is_global = 0;
  }
  qp_attr.ah_attr.dlid = info.lid;
  qp_attr.ah_attr.sl = 0;
  qp_attr.ah_attr.src_path_bits = 0;
  qp_attr.ah_attr.port_num = info.port;
  int ret = IBVerbs::ibv_modify_qp(this->qp, &qp_attr,
                                   IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                                       IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
  if (ret != 0) {
    std::stringstream err;
    err << "ibv_modify_qp failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
}

void IbQp::rts() {
  struct ibv_qp_attr qp_attr;
  std::memset(&qp_attr, 0, sizeof(struct ibv_qp_attr));
  qp_attr.qp_state = IBV_QPS_RTS;
  qp_attr.timeout = 18;
  qp_attr.retry_cnt = 7;
  qp_attr.rnr_retry = 7;
  qp_attr.sq_psn = 0;
  qp_attr.max_rd_atomic = 1;
  int ret = IBVerbs::ibv_modify_qp(
      this->qp, &qp_attr,
      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
  if (ret != 0) {
    std::stringstream err;
    err << "ibv_modify_qp failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
}

IbQp::WrInfo IbQp::getNewWrInfo() {
  if (this->wrn >= this->maxWrPerSend) {
    std::stringstream err;
    err << "too many outstanding work requests. limit is " << this->maxWrPerSend;
    throw mscclpp::Error(err.str(), ErrorCode::InvalidUsage);
  }
  int wrn = this->wrn;

  ibv_send_wr* wr_ = &this->wrs->data()[wrn];
  ibv_sge* sge_ = &this->sges->data()[wrn];
  wr_->sg_list = sge_;
  wr_->num_sge = 1;
  wr_->next = nullptr;
  if (wrn > 0) {
    (*this->wrs)[wrn - 1].next = wr_;
  }
  this->wrn++;
  return IbQp::WrInfo{wr_, sge_};
}

void IbQp::stageSend(const IbMr* mr, const IbMrInfo& info, uint32_t size, uint64_t wrId, uint64_t srcOffset,
                     uint64_t dstOffset, bool signaled) {
  auto wrInfo = this->getNewWrInfo();
  wrInfo.wr->wr_id = wrId;
  wrInfo.wr->opcode = IBV_WR_RDMA_WRITE;
  wrInfo.wr->send_flags = signaled ? IBV_SEND_SIGNALED : 0;
  wrInfo.wr->wr.rdma.remote_addr = (uint64_t)(info.addr) + dstOffset;
  wrInfo.wr->wr.rdma.rkey = info.rkey;
  wrInfo.sge->addr = (uint64_t)(mr->getBuff()) + srcOffset;
  wrInfo.sge->length = size;
  wrInfo.sge->lkey = mr->getLkey();
  if (signaled) (this->numSignaledStagedItems)++;
}

void IbQp::stageAtomicAdd(const IbMr* mr, const IbMrInfo& info, uint64_t wrId, uint64_t dstOffset, uint64_t addVal,
                          bool signaled) {
  auto wrInfo = this->getNewWrInfo();
  wrInfo.wr->wr_id = wrId;
  wrInfo.wr->opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
  wrInfo.wr->send_flags = signaled ? IBV_SEND_SIGNALED : 0;
  wrInfo.wr->wr.atomic.remote_addr = (uint64_t)(info.addr) + dstOffset;
  wrInfo.wr->wr.atomic.rkey = info.rkey;
  wrInfo.wr->wr.atomic.compare_add = addVal;
  wrInfo.sge->addr = (uint64_t)(mr->getBuff());
  wrInfo.sge->length = sizeof(uint64_t);  // atomic op is always on uint64_t
  wrInfo.sge->lkey = mr->getLkey();
  if (signaled) (this->numSignaledStagedItems)++;
}

void IbQp::stageSendWithImm(const IbMr* mr, const IbMrInfo& info, uint32_t size, uint64_t wrId, uint64_t srcOffset,
                            uint64_t dstOffset, bool signaled, unsigned int immData) {
  auto wrInfo = this->getNewWrInfo();
  wrInfo.wr->wr_id = wrId;
  wrInfo.wr->opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
  wrInfo.wr->send_flags = signaled ? IBV_SEND_SIGNALED : 0;
  wrInfo.wr->wr.rdma.remote_addr = (uint64_t)(info.addr) + dstOffset;
  wrInfo.wr->wr.rdma.rkey = info.rkey;
  wrInfo.wr->imm_data = immData;
  wrInfo.sge->addr = (uint64_t)(mr->getBuff()) + srcOffset;
  wrInfo.sge->length = size;
  wrInfo.sge->lkey = mr->getLkey();
  if (signaled) (this->numSignaledStagedItems)++;
}

void IbQp::postSend() {
  if (this->wrn == 0) {
    return;
  }
  struct ibv_send_wr* bad_wr;
  int ret = IBVerbs::ibv_post_send(this->qp, this->wrs->data(), &bad_wr);
  if (ret != 0) {
    std::stringstream err;
    err << "ibv_post_send failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
  this->wrn = 0;
  this->numSignaledPostedItems += this->numSignaledStagedItems;
  this->numSignaledStagedItems = 0;
  if (this->numSignaledPostedItems + 4 > this->cq->cqe) {
    WARN("IB: CQ is almost full ( %d / %d ). The connection needs to be flushed to prevent timeout errors.",
         this->numSignaledPostedItems, this->cq->cqe);
  }
}

int IbQp::pollCq() {
  int wcNum = IBVerbs::ibv_poll_cq(this->cq, this->maxCqPollNum, this->wcs->data());
  if (wcNum > 0) {
    for (int i = 0; i < wcNum; ++i) {
      if ((*this->wcs)[i].status != IBV_WC_SUCCESS) {
        std::stringstream err;
        err << "Work completion at index " << i << " failed with status " << (*this->wcs)[i].status
            << " (" << IBVerbs::ibv_wc_status_str((*this->wcs)[i].status) << ")";
        throw mscclpp::IbError(err.str(), (*this->wcs)[i].status);
      }
      this->numSignaledPostedItems--;
    }
  } else if (wcNum < 0) {
      std::stringstream err;
      err << "ibv_poll_cq failed with negative completion";
      throw mscclpp::IbError(err.str(), errno);
  }
  return wcNum;
}

int IbQp::getWcStatus(int idx) const { return (*this->wcs)[idx].status; }

int IbQp::getNumCqItems() const { return this->numSignaledPostedItems; }

IbCtx::IbCtx(const std::string& devName) : devName(devName) {
  if (!checkPeerMemLoaded()) {
    throw mscclpp::Error("nvidia/amd_peermem kernel module is not loaded", ErrorCode::InternalError);
  }

  int num;
  struct ibv_device** devices = IBVerbs::ibv_get_device_list(&num);
  for (int i = 0; i < num; ++i) {
    if (std::string(devices[i]->name) == devName) {
      this->ctx = IBVerbs::ibv_open_device(devices[i]);
      break;
    }
  }
  IBVerbs::ibv_free_device_list(devices);
  if (this->ctx == nullptr) {
    std::stringstream err;
    err << "ibv_open_device failed (errno " << errno << ", device name << " << devName << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
  this->pd = IBVerbs::ibv_alloc_pd(this->ctx);
  if (this->pd == nullptr) {
    std::stringstream err;
    err << "ibv_alloc_pd failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
}

IbCtx::~IbCtx() {
  this->mrs.clear();
  this->qps.clear();
  if (this->pd != nullptr) {
    IBVerbs::ibv_dealloc_pd(this->pd);
  }
  if (this->ctx != nullptr) {
    IBVerbs::ibv_close_device(this->ctx);
  }
}

bool IbCtx::isPortUsable(int port, struct ibv_port_attr& portAttr) const {
  if (IBVerbs::ibv_query_port_w(this->ctx, port, &portAttr) != 0) {
    std::stringstream err;
    err << "ibv_query_port failed (errno " << errno << ", port << " << port << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
  return portAttr.state == IBV_PORT_ACTIVE &&
         (portAttr.link_layer == IBV_LINK_LAYER_ETHERNET || portAttr.link_layer == IBV_LINK_LAYER_INFINIBAND);
}

int IbCtx::getAnyActivePort(struct ibv_port_attr& portAttr) const {
  struct ibv_device_attr devAttr;
  if (IBVerbs::ibv_query_device(this->ctx, &devAttr) != 0) {
    std::stringstream err;
    err << "ibv_query_device failed (errno " << errno << ")";
    throw mscclpp::IbError(err.str(), errno);
  }
  for (uint8_t port = 1; port <= devAttr.phys_port_cnt; ++port) {
    if (this->isPortUsable(port, portAttr)) {
      return port;
    }
  }
  return -1;
}

IbQp* IbCtx::createQp(int maxCqSize, int maxCqPollNum, int maxSendWr, int maxRecvWr, int maxWrPerSend,
                      int port /*=-1*/) {
  struct ibv_port_attr portAttr;
  if (port == -1) {
    port = this->getAnyActivePort(portAttr);
    if (port == -1) {
      throw mscclpp::Error("No active port found", ErrorCode::InvalidUsage);
    }
  } else if (!this->isPortUsable(port, portAttr)) {
    throw mscclpp::Error("invalid IB port: " + std::to_string(port), ErrorCode::InvalidUsage);
  }
  qps.emplace_back(new IbQp(this->ctx, this->pd, port, portAttr, maxCqSize, maxCqPollNum, maxSendWr, maxRecvWr, maxWrPerSend));
  return qps.back().get();
}

const IbMr* IbCtx::registerMr(void* buff, std::size_t size) {
  mrs.emplace_back(new IbMr(this->pd, buff, size));
  return mrs.back().get();
}

MSCCLPP_API_CPP int getIBDeviceCount() {
  int num;
  auto const& dev = getActiveIbDeviceNames(num);
  return num;
}

std::string getHcaDevices(int deviceIndex) {
  std::string envStr = env()->hcaDevices;
  if (envStr != "") {
    std::vector<std::string> devices;
    std::stringstream ss(envStr);
    std::string device;
    while (std::getline(ss, device, ',')) {
      devices.push_back(device);
    }
    if (deviceIndex >= (int)devices.size()) {
      throw Error("Not enough HCA devices are defined with MSCCLPP_HCA_DEVICES: " + envStr, ErrorCode::InvalidUsage);
    }
    return devices[deviceIndex];
  }
  return "";
}

MSCCLPP_API_CPP std::string getIBDeviceName(Transport ibTransport) {
  int ibTransportIndex;
  switch (ibTransport) {  // TODO: get rid of this ugly switch
    case Transport::IB0:
      ibTransportIndex = 0;
      break;
    case Transport::IB1:
      ibTransportIndex = 1;
      break;
    case Transport::IB2:
      ibTransportIndex = 2;
      break;
    case Transport::IB3:
      ibTransportIndex = 3;
      break;
    case Transport::IB4:
      ibTransportIndex = 4;
      break;
    case Transport::IB5:
      ibTransportIndex = 5;
      break;
    case Transport::IB6:
      ibTransportIndex = 6;
      break;
    case Transport::IB7:
      ibTransportIndex = 7;
      break;
    default:
      throw Error("Not an IB transport", ErrorCode::InvalidUsage);
  }
  std::string userHcaDevice = getHcaDevices(ibTransportIndex);
  if (!userHcaDevice.empty()) {
    return userHcaDevice;
  }

  int num;
  auto const& devices = getActiveIbDeviceNames(num);
  if (ibTransportIndex >= num) {
    std::stringstream ss;
    ss << "IB transport out of range: " << ibTransportIndex << " >= " << num;
    throw Error(ss.str(), ErrorCode::InvalidUsage);
  }
  return devices[ibTransportIndex];
}

MSCCLPP_API_CPP Transport getIBTransportByDeviceName(const std::string& ibDeviceName) {
  int num;
  auto const& devices = getActiveIbDeviceNames(num);
  for (int i = 0; i < num; ++i) {
    if (ibDeviceName == devices[i]) {
      switch (i) {  // TODO: get rid of this ugly switch
        case 0:
          return Transport::IB0;
        case 1:
          return Transport::IB1;
        case 2:
          return Transport::IB2;
        case 3:
          return Transport::IB3;
        case 4:
          return Transport::IB4;
        case 5:
          return Transport::IB5;
        case 6:
          return Transport::IB6;
        case 7:
          return Transport::IB7;
        default:
          throw Error("IB device index out of range", ErrorCode::InvalidUsage);
      }
    }
  }
  throw Error("IB device not found", ErrorCode::InvalidUsage);
}

#else  // !defined(USE_IBVERBS)

MSCCLPP_API_CPP int getIBDeviceCount() { return 0; }

MSCCLPP_API_CPP std::string getIBDeviceName(Transport) { return ""; }

MSCCLPP_API_CPP Transport getIBTransportByDeviceName(const std::string&) { return Transport::Unknown; }

#endif  // !defined(USE_IBVERBS)

}  // namespace mscclpp
