/*
 * Copyright (c) 2021 Ampere Computing LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a daemon that forwards requests and receive responses from SSIF over
 * the D-Bus IPMI Interface.
 */

#include <linux/ipmi_bmc.h>

#include <CLI/CLI.hpp>
#include <boost/asio/completion_condition.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <cstring>

/* Max length of ipmi ssif message included netfn and cmd field */
constexpr const size_t ipmiSsifPayloadMax = 254;

/* IPMI App NetFn 0x06, Cmd 0x57 - Get System Interface Capabilities. */
constexpr uint8_t ipmiNetFnApp = 0x06;
constexpr uint8_t ipmiCmdGetSysIfCap = 0x57;
constexpr uint8_t ipmiSsifIfType = 0x00;
constexpr uint8_t ipmiSsifCapFlags = 0x80;
constexpr uint8_t ipmiSsifMaxXmitMsgSize = 0xFF;
constexpr uint8_t ipmiSsifMaxRecvMsgSize = 0xFF;
/* netfn/lun byte + cmd byte */
constexpr size_t ipmiHdrSize = 2;
/* completion code byte */
constexpr size_t ipmiCcSize = 1;
/* reserved byte in Get System Interface Capabilities response */
constexpr uint8_t ipmiSsifRsvd = 0x00;
/* payloadLen: ifType + capFlags + maxXmit + maxRecv + reserved */
constexpr size_t ipmiSsifCapPayloadLen = 5;
/* total IPMI length field: hdr + cc + payload */
constexpr uint32_t ipmiSsifCapLenField =
    ipmiHdrSize + ipmiCcSize + ipmiSsifCapPayloadLen;

using phosphor::logging::level;
using phosphor::logging::log;

struct IpmiCmd
{
    uint8_t netfn;
    uint8_t lun;
    uint8_t cmd;
};

struct IpmiSsifMsgHeader
{
    unsigned int len;
    uint8_t msgNum;
} __attribute((packed));

static constexpr std::string_view devBase = "/dev/ipmi-ssif-host";
static constexpr std::string_view nameBase = "ipmi_ssif";
/* SSIF use IPMI SSIF channel */

/* The timer of driver is set to 15 seconds, need to send
 * response before timeout occurs
 */
static constexpr const unsigned int hostReqTimeout = 14000000;

class SsifChannel
{
  public:
    static constexpr size_t ssifMessageSize =
        ipmiSsifPayloadMax + sizeof(IpmiSsifMsgHeader);
    size_t sizeofLenField = sizeof(IpmiSsifMsgHeader);
    static constexpr uint8_t netFnShift = 2;
    static constexpr uint8_t lunMask = (1 << netFnShift) - 1;

    SsifChannel(std::shared_ptr<boost::asio::io_context>& io,
                std::shared_ptr<sdbusplus::asio::connection>& bus,
                const std::string& device, const std::string& name,
                bool verbose, bool logRaw);
    bool initOK() const
    {
        return dev.is_open();
    }
    void channelAbort(const char* msg, const boost::system::error_code& ec);
    void asyncRead();
    using IpmiDbusRspType =
        std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;

    void afterMethodCall(const boost::system::error_code& ec,
                         const IpmiDbusRspType& response, uint8_t msgNum);
    void processMessage(const boost::system::error_code& ecRd, size_t rlen);
    // reqCmd captured by value at arm time to frame the keep-alive
    void rspTimerHandler(const boost::system::error_code& ec, IpmiCmd reqCmd);
    int showNumOfReqNotRsp() const;
    boost::asio::posix::stream_descriptor dev;
    IpmiCmd prevReqCmd{};
    /* Set when a timeout response has already been sent for the current
     * request; cleared on each new incoming request.  Ensures any late
     * D-Bus response is dropped so the host never receives two responses
     * for one request. */
    bool timedOut = false;

  protected:
    bool handleGetSysIfCap(uint8_t netfn, uint8_t cmd,
                           const std::vector<uint8_t>& data);
    std::array<uint8_t, ssifMessageSize> xferBuffer{};
    std::shared_ptr<boost::asio::io_context> io;
    std::shared_ptr<sdbusplus::asio::connection> bus;
    std::shared_ptr<sdbusplus::asio::object_server> server;
    bool verbose;
    bool logRaw;
    /* This variable is always 0 when a request is responded properly,
     * any value larger than 0 meaning there is/are request(s) which
     * not processed properly
     * */
    int numberOfReqNotRsp = 0;
    // consecutive read failures; bail out only after a persistent run
    size_t consecutiveReadErrors = 0;
    static constexpr size_t maxConsecutiveReadErrors = 10;

    boost::asio::steady_timer rspTimer;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::unique_ptr<SsifChannel> ssifchannel = nullptr;

SsifChannel::SsifChannel(std::shared_ptr<boost::asio::io_context>& io,
                         std::shared_ptr<sdbusplus::asio::connection>& bus,
                         const std::string& device, const std::string& name,
                         bool verbose, bool logRaw) :
    dev(*io), io(io), bus(bus), verbose(verbose), logRaw(logRaw), rspTimer(*io)
{
    std::string devName(devBase);
    if (!device.empty())
    {
        devName = device;
    }

    // open device
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    int fd = open(devName.c_str(), O_RDWR | O_NONBLOCK);
    if (fd < 0)
    {
        std::string msgToLog = "Couldn't open SSIF driver with flags O_RDWR."
                               " FILENAME=" +
                               devName + " ERROR=" + strerror(errno);
        log<level::ERR>(msgToLog.c_str());
        return;
    }

    dev.assign(fd);

    asyncRead();
    // register interfaces...
    server = std::make_shared<sdbusplus::asio::object_server>(bus);
    std::string objPath = "/xyz/openbmc_project/Ipmi/Channel/" + name;
    std::string ifaceName = "xyz.openbmc_project.Ipmi.Channel." + name;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server->add_interface(objPath, ifaceName);
    iface->initialize();
}

void SsifChannel::channelAbort(const char* msg,
                               const boost::system::error_code& ec)
{
    std::string msgToLog = std::string(msg) + " ERROR=" + ec.message();
    log<level::ERR>(msgToLog.c_str());
    // bail; maybe a restart from systemd can clear the error
    io->stop();
}

void SsifChannel::asyncRead()
{
    boost::asio::async_read(
        dev, boost::asio::buffer(xferBuffer, xferBuffer.size()),
        boost::asio::transfer_at_least(2),
        [this](const boost::system::error_code& ec, size_t rlen) {
            processMessage(ec, rlen);
        });
}

bool SsifChannel::handleGetSysIfCap(uint8_t netfn, uint8_t cmd,
                                    const std::vector<uint8_t>& data)
{
    if (netfn != ipmiNetFnApp || cmd != ipmiCmdGetSysIfCap)
    {
        return false;
    }
    if (data.empty() || data[0] != ipmiSsifIfType)
    {
        return false;
    }

    std::vector<uint8_t> rsp(sizeof(ipmiSsifCapLenField) + ipmiHdrSize +
                             ipmiCcSize + ipmiSsifCapPayloadLen);
    std::memcpy(rsp.data(), &ipmiSsifCapLenField, sizeof(ipmiSsifCapLenField));
    size_t idx = sizeof(ipmiSsifCapLenField);
    rsp[idx++] = static_cast<uint8_t>(
        ((ipmiNetFnApp + 1) << netFnShift) | (prevReqCmd.lun & lunMask));
    rsp[idx++] = ipmiCmdGetSysIfCap;
    rsp[idx++] = ipmiSsifRsvd;
    rsp[idx++] = ipmiSsifRsvd;
    rsp[idx++] = ipmiSsifCapFlags;
    rsp[idx++] = ipmiSsifMaxXmitMsgSize;
    rsp[idx++] = ipmiSsifMaxRecvMsgSize;

    numberOfReqNotRsp--;
    rspTimer.cancel();
    boost::system::error_code ecWr;
    size_t wlen = boost::asio::write(dev, boost::asio::buffer(rsp), ecWr);
    if (ecWr || wlen != rsp.size())
    {
        log<level::ERR>("handleGetSysIfCap: failed to send response");
    }
    return true;
}

int SsifChannel::showNumOfReqNotRsp() const
{
    return numberOfReqNotRsp;
}

void SsifChannel::rspTimerHandler(const boost::system::error_code& ec,
                                  IpmiCmd reqCmd)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }
    std::vector<uint8_t> rsp;
    constexpr uint8_t ccResponseNotAvailable = 0xce;
    rsp.resize(sizeofLenField + sizeof(reqCmd.cmd) + sizeof(reqCmd.netfn) +
               sizeof(ccResponseNotAvailable));
    std::string msgToLog =
        "timeout, send response to keep host alive"
        " netfn=" +
        std::to_string(reqCmd.netfn) + " lun=" + std::to_string(reqCmd.lun) +
        " cmd=" + std::to_string(reqCmd.cmd) +
        " cc=" + std::to_string(ccResponseNotAvailable) +
        " numberOfReqNotRsp=" + std::to_string(showNumOfReqNotRsp());
    log<level::INFO>(msgToLog.c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    unsigned int* t = reinterpret_cast<unsigned int*>(rsp.data());
    *t = 3;
    rsp[sizeofLenField] = ((reqCmd.netfn + 1) << SsifChannel::netFnShift) |
                          (reqCmd.lun & SsifChannel::lunMask);
    rsp[sizeofLenField + 1] = reqCmd.cmd;
    rsp[sizeofLenField + 2] = ccResponseNotAvailable;

    ssifchannel->timedOut = true;

    boost::system::error_code ecWr;

    size_t wlen = boost::asio::write(dev, boost::asio::buffer(rsp), ecWr);
    if (ecWr || wlen != rsp.size())
    {
        msgToLog =
            "Failed to send ssif respond message:"
            " size=" +
            std::to_string(wlen) + " expect=" + std::to_string(rsp.size()) +
            " error=" + ecWr.message() +
            " netfn=" + std::to_string(reqCmd.netfn + 1) +
            " lun=" + std::to_string(reqCmd.lun) +
            " cmd=" + std::to_string(rsp[sizeofLenField + 1]) +
            " cc=" + std::to_string(ccResponseNotAvailable);
        log<level::ERR>(msgToLog.c_str());
    }
}

void SsifChannel::afterMethodCall(const boost::system::error_code& ec,
                                  const IpmiDbusRspType& response,
                                  uint8_t msgNum)
{
    std::vector<uint8_t> rsp;
    const auto& [netfn, lun, cmd, cc, payload] = response;
    numberOfReqNotRsp--;
    if (ec)
    {
        std::string msgToLog =
            "ssif<->ipmid bus error:"
            " netfn=" +
            std::to_string(netfn) + " lun=" + std::to_string(lun) +
            " cmd=" + std::to_string(cmd) + " error=" + ec.message();
        log<level::ERR>(msgToLog.c_str());
        rsp.resize(sizeofLenField + sizeof(netfn) + sizeof(cmd) + sizeof(cc));
        /* if dbusTimeout, just return and do not send any response
         * to let host continue with other commands, response here
         * is potentially make the response duplicated
         * */
        return;
    }

    if (timedOut ||
        (prevReqCmd.netfn != (netfn - 1) || prevReqCmd.lun != lun ||
         prevReqCmd.cmd != cmd) ||
        ((prevReqCmd.netfn == (netfn - 1) && prevReqCmd.lun == lun &&
          prevReqCmd.cmd == cmd) &&
         numberOfReqNotRsp != 0))
    {
        /* Only send response to the last request command to void
         * duplicated response which makes host driver confused and
         * failed to create interface
         *
         * Drop responses which are (1) different from the request
         * (2) parameters are the same as request but handshake flow
         * are in duplicated request state
         * */
        if (verbose)
        {
            std::string msgToLog =
                "Drop ssif respond message with"
                " len=" +
                std::to_string(payload.size() + 3) +
                " netfn=" + std::to_string(netfn) +
                " lun=" + std::to_string(lun) + " cmd=" + std::to_string(cmd) +
                " cc=" + std::to_string(cc) +
                " numberOfReqNotRsp=" + std::to_string(numberOfReqNotRsp);
            log<level::INFO>(msgToLog.c_str());
        }
        return;
    }
    rsp.resize(sizeofLenField + sizeof(netfn) + sizeof(cmd) + sizeof(cc) +
               payload.size());

    // write the response
    auto rspIter = rsp.begin();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    struct IpmiSsifMsgHeader* header =
        reinterpret_cast<struct IpmiSsifMsgHeader*>(&rspIter[0]);
    header->len = payload.size() + 3;
    header->msgNum = msgNum;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    unsigned int* p = reinterpret_cast<unsigned int*>(&rspIter[0]);
    *p = payload.size() + 3;
    rspIter[sizeofLenField] = (netfn << netFnShift) | (lun & lunMask);
    rspIter[sizeofLenField + 1] = cmd;
    rspIter[sizeofLenField + 2] = cc;
    if (static_cast<unsigned int>(!payload.empty()) != 0U)
    {
        std::copy(payload.cbegin(), payload.cend(),
                  rspIter + sizeofLenField + 3);
    }
    if (verbose)
    {
        std::string msgToLog =
            "Send ssif respond message with"
            " len=" +
            std::to_string(payload.size() + 3) +
            " netfn=" + std::to_string(netfn) + " lun=" + std::to_string(lun) +
            " cmd=" + std::to_string(cmd) + " cc=" + std::to_string(cc) +
            " numberOfReqNotRsp=" + std::to_string(numberOfReqNotRsp);
        log<level::INFO>(msgToLog.c_str());
        if (logRaw)
        {
            std::stringstream ss;
            for (uint8_t msg : rsp)
            {
                ss << "0x" << std::uppercase << std::setfill('0')
                   << std::setw(2) << std::hex << static_cast<unsigned int>(msg)
                   << " ";
            }
            std::string rawMsgToLog = "Raw Msg Data: " + ss.str();
            log<level::INFO>(rawMsgToLog.c_str());
        }
    }
    boost::system::error_code ecWr;
    size_t wlen = boost::asio::write(dev, boost::asio::buffer(rsp), ecWr);
    if (ecWr || wlen != rsp.size())
    {
        std::string msgToLog =
            "Failed to send ssif respond message:"
            " size=" +
            std::to_string(wlen) + " expect=" + std::to_string(rsp.size()) +
            " error=" + ecWr.message() + " netfn=" + std::to_string(netfn) +
            " lun=" + std::to_string(lun) + " cmd=" + std::to_string(cmd) +
            " cc=" + std::to_string(cc);
        log<level::ERR>(msgToLog.c_str());
    }
    rspTimer.cancel();
}

void SsifChannel::processMessage(const boost::system::error_code& ecRd,
                                 size_t rlen)
{
    if (ecRd || rlen < 2)
    {
        // descriptor torn down (normal shutdown); nothing to recover
        if (ecRd == boost::asio::error::operation_aborted)
        {
            return;
        }
        // transient read error: re-arm instead of killing the daemon
        if (++consecutiveReadErrors > maxConsecutiveReadErrors)
        {
            channelAbort("Too many consecutive SSIF read errors", ecRd);
            return;
        }
        std::string msgToLog =
            "Failed to read req msg, re-arming. ERROR=" + ecRd.message() +
            " rlen=" + std::to_string(rlen) +
            " consecutiveReadErrors=" + std::to_string(consecutiveReadErrors);
        log<level::ERR>(msgToLog.c_str());
        asyncRead();
        return;
    }
    consecutiveReadErrors = 0;
    asyncRead();

    // need header + netfn/lun + cmd; drop short frames (avoids first>last)
    if (rlen < sizeofLenField + 2)
    {
        std::string msgToLog =
            "Drop too-short ssif request message, len=" + std::to_string(rlen);
        log<level::ERR>(msgToLog.c_str());
        return;
    }

    const auto* rawIter = xferBuffer.cbegin();
    const auto* rawEnd = rawIter + rlen;
    uint8_t netfn = rawIter[sizeofLenField] >> netFnShift;
    uint8_t lun = rawIter[sizeofLenField] & lunMask;
    uint8_t cmd = rawIter[sizeofLenField + 1];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const struct IpmiSsifMsgHeader* header =
        reinterpret_cast<const struct IpmiSsifMsgHeader*>(&rawIter[0]);

    /* keep track of previous request */
    prevReqCmd.netfn = netfn;
    prevReqCmd.lun = lun;
    prevReqCmd.cmd = cmd;

    /* there is a request coming */
    numberOfReqNotRsp++;
    timedOut = false;
    // start response timer; capture this request's cmd for the keep-alive
    rspTimer.expires_after(std::chrono::microseconds(hostReqTimeout));
    rspTimer.async_wait(
        [this, reqCmd{prevReqCmd}](const boost::system::error_code& ec) {
            rspTimerHandler(ec, reqCmd);
        });

    if (verbose)
    {
        unsigned int lenRecv = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const unsigned int* p = reinterpret_cast<const unsigned int*>(rawIter);
        lenRecv = p[0];
        std::string msgToLog =
            "Read ssif request message with"
            " len=" +
            std::to_string(lenRecv) + " netfn=" + std::to_string(netfn) +
            " lun=" + std::to_string(lun) + " cmd=" + std::to_string(cmd) +
            " numberOfReqNotRsp=" + std::to_string(numberOfReqNotRsp);
        log<level::INFO>(msgToLog.c_str());

        if (logRaw)
        {
            std::stringstream ss;
            for (unsigned int msgPos = sizeofLenField;
                 msgPos < (lenRecv + sizeofLenField) && msgPos < rlen; msgPos++)
            {
                ss << "0x" << std::uppercase << std::setfill('0')
                   << std::setw(2) << std::hex
                   << static_cast<unsigned int>(rawIter[msgPos]) << " ";
            }
            std::string rawMsgToLog = "Raw Msg Data: " + ss.str();
            log<level::INFO>(rawMsgToLog.c_str());
        }
    }
    // copy out payload
    std::vector<uint8_t> data(rawIter + sizeofLenField + 2, rawEnd);
    // non-session bridges still need to pass an empty options map
    std::map<std::string, std::variant<int>> options;
    if (handleGetSysIfCap(netfn, cmd, data))
    {
        return;
    }
    static constexpr const char* ipmiQueueService =
        "xyz.openbmc_project.Ipmi.Host";
    static constexpr const char* ipmiQueuePath = "/xyz/openbmc_project/Ipmi";
    static constexpr const char* ipmiQueueIntf =
        "xyz.openbmc_project.Ipmi.Server";
    static constexpr const char* ipmiQueueMethod = "execute";
    /* now, we do not care dbus timeout, since we already have actions
     * before dbus timeout occurs
     */
    static constexpr unsigned int dbusTimeout = 60000000;
    bus->async_method_call_timed(
        [this, msgNum{header->msgNum}](const boost::system::error_code& ec,
                                       const IpmiDbusRspType& response) {
            afterMethodCall(ec, response, msgNum);
        },
        ipmiQueueService, ipmiQueuePath, ipmiQueueIntf, ipmiQueueMethod,
        dbusTimeout, netfn, lun, cmd, data, options);
}

int main(int argc, char* argv[])
try
{
    CLI::App app("SSIF IPMI bridge");
    std::string device;
    std::string name(nameBase);
    app.add_option("-d,--device", device,
                   "use <DEVICE> file. Default is /dev/ipmi-ssif-host");
    app.add_option("-n,--name", name,
                   "Channel name used in D-Bus service name and object path. "
                   "Default is ipmi_ssif");
    bool verbose = false;
    bool raw = false;
    app.add_option("-v,--verbose", verbose, "print more verbose output");
    app.add_option("-r,--logRaw", raw,
                   "Log Raw Messages (verbose must be set as well)");
    CLI11_PARSE(app, argc, argv);

    auto io = std::make_shared<boost::asio::io_context>();

    auto bus = std::make_shared<sdbusplus::asio::connection>(*io);
    std::string dbusName = "xyz.openbmc_project.Ipmi.Channel." + name;
    bus->request_name(dbusName.c_str());
    // Create the SSIF channel, listening on D-Bus and on the SSIF device
    ssifchannel =
        std::make_unique<SsifChannel>(io, bus, device, name, verbose, raw);
    if (!ssifchannel->initOK())
    {
        return EXIT_FAILURE;
    }

    io->run();

    return 0;
}
catch (const std::exception& e)
{
    std::string msg =
        std::string("ssifbridge: unhandled exception in main: ") + e.what();
    log<level::ERR>(msg.c_str());
    return EXIT_FAILURE;
}
catch (...)
{
    log<level::ERR>("ssifbridge: unknown unhandled exception in main");
    return EXIT_FAILURE;
}
