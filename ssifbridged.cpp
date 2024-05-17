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

#include <getopt.h>
#include <linux/ipmi_bmc.h>

#include <CLI/CLI.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/asio/completion_condition.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/timer.hpp>

#include <iostream>

<<<<<<< HEAD
/* Max length of ipmi ssif message included netfn and cmd field */
#define IPMI_SSIF_PAYLOAD_MAX         254

using namespace phosphor::logging;
||||||| 88cdf7d
using namespace phosphor::logging;
=======
/* Max length of ipmi ssif message included netfn and cmd field */
constexpr const size_t ipmiSsifPayloadMax = 254;
>>>>>>> origin/master

<<<<<<< HEAD
struct ipmi_ssif_msg_header {
    unsigned int len;
    uint8_t msg_num;
} __attribute((packed));

static constexpr const char devBase[] = "/dev/ipmi-ssif-host";
||||||| 88cdf7d
static constexpr const char devBase[] = "/dev/ipmi-ssif-host";
=======
using phosphor::logging::level;
using phosphor::logging::log;

struct IpmiCmd
{
    uint8_t netfn;
    uint8_t lun;
    uint8_t cmd;
};

static constexpr std::string_view devBase = "/dev/ipmi-ssif-host";
>>>>>>> origin/master
/* SSIF use IPMI SSIF channel */

/* The timer of driver is set to 15 seconds, need to send
 * response before timeout occurs
 */
static constexpr const unsigned int hostReqTimeout = 14000000;

class SsifChannel
{
  public:
<<<<<<< HEAD
    static constexpr size_t ssifMessageSize = IPMI_SSIF_PAYLOAD_MAX +
                                              sizeof(unsigned int);
    size_t sizeofLenField = sizeof(struct ipmi_ssif_msg_header);
||||||| 88cdf7d
    static constexpr size_t ssifMessageSize = 255;
=======
    static constexpr size_t ssifMessageSize = ipmiSsifPayloadMax +
                                              sizeof(unsigned int);
    size_t sizeofLenField = sizeof(unsigned int);
>>>>>>> origin/master
    static constexpr uint8_t netFnShift = 2;
    static constexpr uint8_t lunMask = (1 << netFnShift) - 1;

    SsifChannel(std::shared_ptr<boost::asio::io_context>& io,
<<<<<<< HEAD
                   std::shared_ptr<sdbusplus::asio::connection>& bus,
                   const std::string& channel, bool verbose, bool logRaw);
||||||| 88cdf7d
                   std::shared_ptr<sdbusplus::asio::connection>& bus,
                   const std::string& channel, bool verbose);
=======
                std::shared_ptr<sdbusplus::asio::connection>& bus,
                const std::string& device, bool verbose);
>>>>>>> origin/master
    bool initOK() const
    {
        return dev.is_open();
    }
    void channelAbort(const char* msg, const boost::system::error_code& ec);
    void asyncRead();
    using IpmiDbusRspType =
        std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;

    void afterMethodCall(const boost::system::error_code& ec,
                         const IpmiDbusRspType& response);
    void processMessage(const boost::system::error_code& ecRd, size_t rlen);
    int showNumOfReqNotRsp() const;
    boost::asio::posix::stream_descriptor dev;
    IpmiCmd prevReqCmd{};

  protected:
    std::array<uint8_t, ssifMessageSize> xferBuffer{};
    std::shared_ptr<boost::asio::io_context> io;
    std::shared_ptr<sdbusplus::asio::connection> bus;
    std::shared_ptr<sdbusplus::asio::object_server> server;
    bool verbose;
<<<<<<< HEAD
    bool logRaw;
||||||| 88cdf7d
=======
    /* This variable is always 0 when a request is responsed properly,
     * any value larger than 0 meaning there is/are request(s) which
     * not processed properly
     * */
    int numberOfReqNotRsp = 0;

    boost::asio::steady_timer rspTimer;
>>>>>>> origin/master
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::unique_ptr<SsifChannel> ssifchannel = nullptr;

SsifChannel::SsifChannel(std::shared_ptr<boost::asio::io_context>& io,
                         std::shared_ptr<sdbusplus::asio::connection>& bus,
<<<<<<< HEAD
                         const std::string& device, bool verbose, bool logRaw) :
    io(io),
    bus(bus), 
    verbose(verbose), logRaw(logRaw)
||||||| 88cdf7d
                         const std::string& device, bool verbose) :
    io(io),
    bus(bus), verbose(verbose)
=======
                         const std::string& device, bool verbose) :
    dev(*io),
    io(io), bus(bus), verbose(verbose), rspTimer(*io)
>>>>>>> origin/master
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
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server->add_interface("/xyz/openbmc_project/Ipmi/Channel/ipmi_ssif",
                              "xyz.openbmc_project.Ipmi.Channel.ipmi_ssif");
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
    boost::asio::async_read(dev,
                            boost::asio::buffer(xferBuffer, xferBuffer.size()),
                            boost::asio::transfer_at_least(sizeofLenField),
                            [this](const boost::system::error_code& ec,
                                   size_t rlen) { processMessage(ec, rlen); });
}

int SsifChannel::showNumOfReqNotRsp() const
{
    return numberOfReqNotRsp;
}

void rspTimerHandler(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }
    std::vector<uint8_t> rsp;
    constexpr uint8_t ccResponseNotAvailable = 0xce;
    IpmiCmd& prevReqCmd = ssifchannel->prevReqCmd;
    rsp.resize(ssifchannel->sizeofLenField + sizeof(prevReqCmd.cmd) +
               sizeof(prevReqCmd.netfn) + sizeof(ccResponseNotAvailable));
    std::string msgToLog = "timeout, send response to keep host alive"
                           " netfn=" +
                           std::to_string(prevReqCmd.netfn) +
                           " lun=" + std::to_string(prevReqCmd.lun) +
                           " cmd=" + std::to_string(prevReqCmd.cmd) +
                           " cc=" + std::to_string(ccResponseNotAvailable) +
                           " numberOfReqNotRsp=" +
                           std::to_string(ssifchannel->showNumOfReqNotRsp());
    log<level::INFO>(msgToLog.c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    unsigned int* t = reinterpret_cast<unsigned int*>(rsp.data());
    *t = 3;
    rsp[ssifchannel->sizeofLenField] = ((prevReqCmd.netfn + 1)
                                        << ssifchannel->netFnShift) |
                                       (prevReqCmd.lun & ssifchannel->lunMask);
    rsp[ssifchannel->sizeofLenField + 1] = prevReqCmd.cmd;
    rsp[ssifchannel->sizeofLenField + 2] = ccResponseNotAvailable;

    boost::system::error_code ecWr;

    size_t wlen = boost::asio::write(ssifchannel->dev, boost::asio::buffer(rsp),
                                     ecWr);
    if (ecWr || wlen != rsp.size())
    {
        msgToLog =
            "Failed to send ssif respond message:"
            " size=" +
            std::to_string(wlen) + " expect=" + std::to_string(rsp.size()) +
            " error=" + ecWr.message() +
            " netfn=" + std::to_string(prevReqCmd.netfn + 1) +
            " lun=" + std::to_string(prevReqCmd.lun) +
            " cmd=" + std::to_string(rsp[ssifchannel->sizeofLenField + 1]) +
            " cc=" + std::to_string(ccResponseNotAvailable);
        log<level::ERR>(msgToLog.c_str());
    }
}

void SsifChannel::afterMethodCall(const boost::system::error_code& ec,
                                  const IpmiDbusRspType& response)
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

    if ((prevReqCmd.netfn != (netfn - 1) || prevReqCmd.lun != lun ||
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
         * are in dupplicate request state
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
    size_t processed = 0;

    if (ecRd || rlen < sizeofLenField)
    {
        channelAbort("Failed to read req msg", ecRd);
        return;
    }
<<<<<<< HEAD
    auto rawIterStart = xferBuffer.cbegin();
||||||| 88cdf7d
    async_read();
=======
    asyncRead();

    const auto* rawIter = xferBuffer.cbegin();
    const auto* rawEnd = rawIter + rlen;
    uint8_t netfn = rawIter[sizeofLenField] >> netFnShift;
    uint8_t lun = rawIter[sizeofLenField] & lunMask;
    uint8_t cmd = rawIter[sizeofLenField + 1];

    /* keep track of previous request */
    prevReqCmd.netfn = netfn;
    prevReqCmd.lun = lun;
    prevReqCmd.cmd = cmd;

    /* there is a request coming */
    numberOfReqNotRsp++;
    /* start response timer */
    rspTimer.expires_after(std::chrono::microseconds(hostReqTimeout));
    rspTimer.async_wait(rspTimerHandler);
>>>>>>> origin/master

<<<<<<< HEAD
    while (processed < rlen)
||||||| 88cdf7d
    auto rawIter = xferBuffer.cbegin();
    auto rawEnd = rawIter + rlen;
    uint8_t netfn = rawIter[1] >> netFnShift;
    uint8_t lun = rawIter[1] & lunMask;
    uint8_t cmd = rawIter[2];
    if (verbose)
=======
    if (verbose)
>>>>>>> origin/master
    {
<<<<<<< HEAD
        auto rawIter = &rawIterStart[processed];
        uint8_t netfn = rawIter[sizeofLenField] >> netFnShift;
        uint8_t lun = rawIter[sizeofLenField] & lunMask;
        uint8_t cmd = rawIter[sizeofLenField + 1];
        struct ipmi_ssif_msg_header *header = (struct ipmi_ssif_msg_header*) &rawIter[0];
        auto rawEnd = rawIter + sizeofLenField + header->len;

        if (verbose)
        {
            unsigned int lenRecv;
            unsigned int *p = (unsigned int *) rawIter;
            lenRecv = p[0];
            std::string msgToLog = "Read ssif request message with"
                    " len=" + std::to_string(lenRecv) +
                    " netfn=" + std::to_string(netfn) +
                    " lun=" + std::to_string(lun) +
                    " cmd=" + std::to_string(cmd);
            log<level::INFO>(msgToLog.c_str());

            if (logRaw)
            {
                std::stringstream ss;
                for (unsigned int msgPos = sizeofLenField; msgPos < (lenRecv + sizeofLenField); msgPos++)
                {
                    ss << "0x" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(rawIter[msgPos]) << " ";
                }
                std::string rawMsgToLog = "Raw Msg Data: " + ss.str();
                log<level::INFO>(rawMsgToLog.c_str());
            }
        }

        // copy out payload
        std::vector<uint8_t> data(rawIter + sizeofLenField + 2, rawEnd);
        // non-session bridges still need to pass an empty options map
        std::map<std::string, std::variant<int>> options;
        // the response is a tuple because dbus can only return a single value
        using IpmiDbusRspType = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t,
                                           std::vector<uint8_t>>;
        static constexpr const char ipmiQueueService[] =
            "xyz.openbmc_project.Ipmi.Host";
        static constexpr const char ipmiQueuePath[] =
            "/xyz/openbmc_project/Ipmi";
        static constexpr const char ipmiQueueIntf[] =
            "xyz.openbmc_project.Ipmi.Server";
        static constexpr const char ipmiQueueMethod[] = "execute";
        static constexpr int dbusTimeout = 40000000;
        bus->async_method_call_timed(
            [this, netfnCap{netfn}, lunCap{lun},
             cmdCap{cmd}, msg_num{header->msg_num}](const boost::system::error_code& ec,
                          const IpmiDbusRspType& response) {
                std::vector<uint8_t> rsp;
                const auto& [netfn, lun, cmd, cc, payload] = response;
                if (ec)
                {
                    std::string msgToLog = "ssif<->ipmid bus error:"
                            " netfn=" + std::to_string(netfn) +
                            " lun=" + std::to_string(lun) +
                            " cmd=" + std::to_string(cmd) +
                            " error=" + ec.message();
                    log<level::ERR>(msgToLog.c_str());
                    rsp.resize(sizeofLenField + sizeof(netfn) + sizeof(cmd) +
                               sizeof(cc));
                    /* if dbusTimeout, just return and do not send any response
                     * to let host continue with other commands, response here
                     * is potentionally make the response duplicated
                     * */
                    return;
                }
                else
                {
                    rsp.resize(sizeofLenField + sizeof(netfn) + sizeof(cmd) +
                               sizeof(cc) + payload.size());
                        // write the response
                    auto rspIter = rsp.begin();
                    struct ipmi_ssif_msg_header *header = (struct ipmi_ssif_msg_header*) &rspIter[0];
                    header->len = payload.size() + 3;
                    header->msg_num = msg_num;
                    rspIter[sizeofLenField] = (netfn << netFnShift) | (lun & lunMask);
                    rspIter[sizeofLenField + 1] = cmd;
                    rspIter[sizeofLenField + 2] = cc;
                    if (payload.size())
                    {
                        std::copy(payload.cbegin(), payload.cend(),
                                rspIter + sizeofLenField + 3);
                    }
                }
                if (verbose)
                {
                    std::string msgToLog = "Send ssif respond message with"
                            " len=" + std::to_string(payload.size() + 3) +
                            " netfn=" + std::to_string(netfn) +
                            " lun=" + std::to_string(lun) +
                            " cmd=" + std::to_string(cmd) +
                            " cc=" + std::to_string(cc);
                    log<level::INFO>(msgToLog.c_str());

                    if (logRaw)
                    {
                        std::stringstream ss;
                        for (unsigned int msgPos = 0; msgPos < rsp.size(); msgPos++)
                        {
                            ss << "0x" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(rsp[msgPos]) << " ";
                        }
                        std::string rawMsgToLog = "Raw Msg Data: " + ss.str();
                        log<level::INFO>(rawMsgToLog.c_str());
                    }
                }
                boost::system::error_code ecWr;
                size_t wlen =
                    boost::asio::write(*dev, boost::asio::buffer(rsp), ecWr);
                if (ecWr || wlen != rsp.size())
                {
                    std::string msgToLog = "Failed to send ssif respond message:"
                            " size=" + std::to_string(wlen) +
                            " expect=" + std::to_string(rsp.size()) +
                            " error=" + ecWr.message() +
                            " netfn=" + std::to_string(netfn) +
                            " lun=" + std::to_string(lun) +
                            " cmd=" + std::to_string(cmd) +
                            " cc=" + std::to_string(cc);
                    log<level::ERR>(msgToLog.c_str());
                }
            },
            ipmiQueueService, ipmiQueuePath, ipmiQueueIntf, ipmiQueueMethod, dbusTimeout,
            netfn, lun, cmd, data, options);
        processed = rawEnd - rawIterStart;
    }

    async_read();
||||||| 88cdf7d
        std::string msgToLog = "Read ssif request message with"
                " len=" + std::to_string(rawIter[0] + 1) +
                " netfn=" + std::to_string(netfn) +
                " lun=" + std::to_string(lun) +
                " cmd=" + std::to_string(cmd);
        log<level::INFO>(msgToLog.c_str());
    }
    // copy out payload
    std::vector<uint8_t> data(&rawIter[3], rawEnd);
    // non-session bridges still need to pass an empty options map
    std::map<std::string, std::variant<int>> options;
    // the response is a tuple because dbus can only return a single value
    using IpmiDbusRspType = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t,
                                       std::vector<uint8_t>>;
    static constexpr const char ipmiQueueService[] =
        "xyz.openbmc_project.Ipmi.Host";
    static constexpr const char ipmiQueuePath[] =
        "/xyz/openbmc_project/Ipmi";
    static constexpr const char ipmiQueueIntf[] =
        "xyz.openbmc_project.Ipmi.Server";
    static constexpr const char ipmiQueueMethod[] = "execute";
    bus->async_method_call(
        [this, netfnCap{netfn}, lunCap{lun},
         cmdCap{cmd}](const boost::system::error_code& ec,
                      const IpmiDbusRspType& response) {
            std::vector<uint8_t> rsp;
            const auto& [netfn, lun, cmd, cc, payload] = response;
            if (ec)
            {
                std::string msgToLog = "ssif<->ipmid bus error:"
                        " netfn=" + std::to_string(netfn) +
                        " lun=" + std::to_string(lun) +
                        " cmd=" + std::to_string(cmd) +
                        " error=" + ec.message();
                log<level::ERR>(msgToLog.c_str());
                // send unspecified error for a D-Bus error
                constexpr uint8_t ccResponseNotAvailable = 0xce;
                rsp.resize(sizeof(uint8_t) + sizeof(netfn) + sizeof(cmd) +
                           sizeof(cc));
                rsp[0] = 3;
                rsp[1] =
                    ((netfnCap + 1) << netFnShift) | (lunCap & lunMask);
                rsp[2] = cmdCap;
                rsp[3] = ccResponseNotAvailable;
            }
            else
            {
                rsp.resize(sizeof(uint8_t) + sizeof(netfn) + sizeof(cmd) +
                           sizeof(cc) + payload.size());

                // write the response
                auto rspIter = rsp.begin();
                rspIter[0] = payload.size() + 3;
                rspIter[1] = (netfn << netFnShift) | (lun & lunMask);
                rspIter[2] = cmd;
                rspIter[3] = cc;
                if (payload.size())
                {
                    std::copy(payload.cbegin(), payload.cend(),
                              &rspIter[4]);
                }
            }
            if (verbose)
            {
                std::string msgToLog = "Send ssif respond message with"
                        " len=" + std::to_string(payload.size() + 3) +
                        " netfn=" + std::to_string(netfn) +
                        " lun=" + std::to_string(lun) +
                        " cmd=" + std::to_string(cmd) +
                        " cc=" + std::to_string(cc);
                log<level::INFO>(msgToLog.c_str());
            }
            boost::system::error_code ecWr;
            size_t wlen =
                boost::asio::write(*dev, boost::asio::buffer(rsp), ecWr);
            if (ecWr || wlen != rsp.size())
            {
                std::string msgToLog = "Failed to send ssif respond message:"
                        " size=" + std::to_string(wlen) +
                        " expect=" + std::to_string(rsp.size()) +
                        " error=" + ecWr.message() +
                        " netfn=" + std::to_string(netfn) +
                        " lun=" + std::to_string(lun) +
                        " cmd=" + std::to_string(cmd) +
                        " cc=" + std::to_string(cc);
                log<level::ERR>(msgToLog.c_str());
            }
        },
        ipmiQueueService, ipmiQueuePath, ipmiQueueIntf, ipmiQueueMethod,
        netfn, lun, cmd, data, options);
=======
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
    }
    // copy out payload
    std::vector<uint8_t> data(rawIter + sizeofLenField + 2, rawEnd);
    // non-session bridges still need to pass an empty options map
    std::map<std::string, std::variant<int>> options;
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
        [this](const boost::system::error_code& ec,
               const IpmiDbusRspType& response) {
        afterMethodCall(ec, response);
    },
        ipmiQueueService, ipmiQueuePath, ipmiQueueIntf, ipmiQueueMethod,
        dbusTimeout, netfn, lun, cmd, data, options);
>>>>>>> origin/master
}

int main(int argc, char* argv[])
{
    CLI::App app("SSIF IPMI bridge");
    std::string device;
    app.add_option("-d,--device", device,
                   "use <DEVICE> file. Default is /dev/ipmi-ssif-host");
    bool verbose = false;
    bool raw = false;
    app.add_option("-v,--verbose", verbose, "print more verbose output");
    app.add_option("-r,--logRaw", raw, "Log Raw Messages (verbose must be set as well)");
    CLI11_PARSE(app, argc, argv);

    auto io = std::make_shared<boost::asio::io_context>();

    auto bus = std::make_shared<sdbusplus::asio::connection>(*io);
    bus->request_name("xyz.openbmc_project.Ipmi.Channel.ipmi_ssif");
    // Create the SSIF channel, listening on D-Bus and on the SSIF device
<<<<<<< HEAD
    SsifChannel ssifchannel(io, bus, device, verbose, raw);
    if (!ssifchannel.initOK())
||||||| 88cdf7d
    SsifChannel ssifchannel(io, bus, device, verbose);
    if (!ssifchannel.initOK())
=======
    ssifchannel = make_unique<SsifChannel>(io, bus, device, verbose);
    if (!ssifchannel->initOK())
>>>>>>> origin/master
    {
        return EXIT_FAILURE;
    }
    io->run();

    return 0;
}
