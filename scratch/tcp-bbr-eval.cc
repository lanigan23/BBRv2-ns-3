#include <iostream>
#include <fstream>
#include <string>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/error-model.h"
#include "ns3/tcp-header.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TcpBbrEval");

static bool firstCwnd = true;
static bool firstSshThr = true;
static bool firstRtt = true;
static bool firstRto = true;
static bool firstPropRtt = true;
static Ptr<OutputStreamWrapper> cWndStream;
static Ptr<OutputStreamWrapper> ssThreshStream;
static Ptr<OutputStreamWrapper> rttStream;
static Ptr<OutputStreamWrapper> rtoStream;
static Ptr<OutputStreamWrapper> propRttStream;
static Ptr<OutputStreamWrapper> nextTxStream;
static Ptr<OutputStreamWrapper> nextRxStream;
static Ptr<OutputStreamWrapper> inFlightStream;
static uint32_t cWndValue;
static uint32_t ssThreshValue;
static bool m_state = false;

static void ChangeDataRate ()
{
    if (!m_state)
    {
        Config::Set ("/NodeList/0/DeviceList/0/DataRate", StringValue ("10Mbps"));
        Config::Set ("/NodeList/1/DeviceList/0/DataRate", StringValue ("10Mbps"));
        m_state = false;
    }
    else
    {
        Config::Set ("/NodeList/0/DeviceList/0/DataRate", StringValue ("20Mbps"));
        Config::Set ("/NodeList/1/DeviceList/0/DataRate", StringValue ("20Mbps"));
        m_state = true;
    }
    Simulator::Schedule (Seconds (20), ChangeDataRate);
}

static void
CwndTracer (uint32_t oldval, uint32_t newval)
{
    if (firstCwnd)
    {
        *cWndStream->GetStream () << "0.0 " << oldval << std::endl;
        firstCwnd = false;        
    }
    *cWndStream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
    cWndValue = newval;

    if (!firstSshThr)
    {
        *ssThreshStream->GetStream () << Simulator::Now ().GetSeconds () << " " << ssThreshStream << std::endl;
    }
}

static void
SsThreshTracer (uint32_t oldval, uint32_t newval)
{
    if (firstSshThr)
    {
        *ssThreshStream->GetStream () << "0.0 " << oldval << std::endl;
        firstSshThr = false;
    }
    *ssThreshStream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
    ssThreshValue = newval;

    if (!firstCwnd)
    {
        *cWndStream->GetStream () << Simulator::Now ().GetSeconds () << " " << cWndValue << std::endl;
    }
}

static void
RttTracer (Time oldval, Time newval)
{
    if (firstRtt)
    {
        *rttStream->GetStream () << "0.0 " << oldval.GetSeconds () << std::endl;
        firstRtt = false;
    }
    *rttStream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void
RtoTracer (Time oldval, Time newval)
{
    if (firstRto)
    {
        *rtoStream->GetStream () << "0.0 " << oldval.GetSeconds () << std::endl;
        firstRto = false;
    }
    *rttStream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void
PropRttTracer (Time oldval, Time newval)
{
    if (firstPropRtt)
    {
        *propRttStream->GetStream () << "0.0 " << oldval.GetSeconds () << std::endl;
        firstPropRtt = false;
    }
    *propRttStream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void
NextTxTracer (SequenceNumber32 old, SequenceNumber32 nextTx)
{
    NS_UNUSED (old);
    *nextTxStream->GetStream () << Simulator::Now ().GetSeconds () << " " << nextTx << std::endl;
}

static void
InFlightTracer (uint32_t old, uint32_t inFlight)
{
    NS_UNUSED (old);
    *inFlightStream->GetStream () << Simulator::Now ().GetSeconds () << " " << inFlight << std::endl;
}

static void
NextRxTracer (SequenceNumber32 old, SequenceNumber32 nextRx)
{
    NS_UNUSED (old);
    *nextTxStream->GetStream () << Simulator::Now ().GetSeconds () << " " << nextRx << std::endl;
}

static void
TraceCwnd (std::string cwnd_tr_file_name)
{
    AsciiTraceHelper ascii;
    cWndStream = ascii.CreateFileStream (cwnd_tr_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer));
}

static void
TraceSsThresh (std::string ssthresh_tr_file_name)
{
    AsciiTraceHelper ascii;
    ssThreshStream = ascii.CreateFileStream (ssthresh_tr_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/SlowStartThreshold", MakeCallback (&SsThreshTracer));
}

static void
TraceRtt (std::string rtt_tr_file_name)
{
    AsciiTraceHelper ascii;
    rttStream = ascii.CreateFileStream (rtt_tr_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/RTT", MakeCallback (&RttTracer));
}

static void
TraceRto (std::string rto_tr_file_name)
{
    AsciiTraceHelper ascii;
    rtoStream = ascii.CreateFileStream (rto_tr_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/RTO", MakeCallback (&RtoTracer));
}

static void
TracePropRtt (std::string prop_rtt_tr_file_name)
{
    AsciiTraceHelper ascii;
    propRttStream = ascii.CreateFileStream (prop_rtt_tr_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/PropRTT", MakeCallback (&PropRttTracer));
}

static void
TraceNextTx (std::string &next_tx_seq_file_name)
{
    AsciiTraceHelper ascii;
    nextTxStream = ascii.CreateFileStream (next_tx_seq_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/NextTxSequence", MakeCallback (&NextTxTracer));
}

static void
TraceNextRx (std::string &next_rx_seq_file_name)
{
    AsciiTraceHelper ascii;
    nextRxStream = ascii.CreateFileStream (next_rx_seq_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/1/RxBuffer/NextRxSequence", MakeCallback (&NextRxTracer));
}

static void
TraceInflight (std::string &in_flight_file_name)
{
    AsciiTraceHelper ascii;
    inFlightStream = ascii.CreateFileStream (in_flight_file_name.c_str ());
    Config::ConnectWithoutContext ("/NodeList/2/$ns3::TcpL4Protocol/SocketList/0/BytesInFlight", MakeCallback (&InFlightTracer));
}

int main (int argc, char *argv[])
{
    std::string transport_prot = "TcpBbr";
    double error_p = 0.0;
    std::string bandwidth = "10Mbps";
    std::string delay = "18ms";
    std::string access_bandwidth = "40Mbps";
    std::string access_delay = "1ms";
    std::string prefix_file_name = "TcpBbrEval";
    uint32_t nLeaf = 1;
    uint64_t data_mbytes = 0;
    uint32_t mtu_bytes = 536;
    uint16_t num_flows = 1;
    uint32_t initialCwnd = 10;
    double minRto = 0.2;
    double duration = 100.00;
    uint32_t run = 0;
    bool pcap = true;
    bool sack = true;
    std::string queue_disc_type = "ns3::PfifoFastQueueDisc";
    std::string recovery = "ns3::TcpClassicRecovery";
    std::string scenario = "1";

    CommandLine cmd;
    cmd.AddValue ("transport_prot", "Transport protocol to use: TcpNewReno, "
                "TcpHybla, TcpHighSpeed, TcpHtcp, TcpVegas, TcpScalable, TcpVeno, "
                "TcpBic, TcpYeah, TcpIllinois, TcpWestwood, TcpWestwoodPlus, TcpLedbat, "
		"TcpLp", transport_prot);
    cmd.AddValue ("error_p", "Packet error rate", error_p);
    cmd.AddValue ("bandwidth", "Bottleneck bandwidth", bandwidth);
    cmd.AddValue ("delay", "Bottleneck delay", delay);
    cmd.AddValue ("access_bandwidth", "Access link bandwidth", access_bandwidth);
    cmd.AddValue ("access_delay", "Access link delay", access_delay);
    cmd.AddValue ("prefix_name", "Prefix of output trace file", prefix_file_name);
    cmd.AddValue ("data", "Number of Megabytes of data to transmit", data_mbytes);
    cmd.AddValue ("mtu", "Size of IP packets to send in bytes", mtu_bytes);
    cmd.AddValue ("num_flows", "Number of flows", num_flows);
    cmd.AddValue ("duration", "Time to allow flows to run in seconds", duration);
    cmd.AddValue ("run", "Run index (for setting repeatable seeds)", run);
    cmd.AddValue ("pcap_tracing", "Enable or disable PCAP tracing", pcap);
    cmd.AddValue ("queue_disc_type", "Queue disc type for gateway (e.g. ns3::CoDelQueueDisc)", queue_disc_type);
    cmd.AddValue ("sack", "Enable or disable SACK option", sack);
    cmd.AddValue ("recovery", "Recovery algorithm type to use (e.g., ns3::TcpPrrRecovery", recovery);
    cmd.AddValue ("nLeaf", "Number of left and right side leaf nodes", nLeaf);
    cmd.AddValue ("scenario", "Scenario", scenario);
    cmd.AddValue ("initialCwnd", "Initial Cwnd", initialCwnd);
    cmd.AddValue ("minRto", "minimum RTO", minRto);
    cmd.Parse (argc, argv);

    transport_prot = std::string ("ns3::") + transport_prot;

    Header* temp_header = new Ipv4Header ();
    uint32_t ip_header = temp_header->GetSerializedSize ();
    NS_LOG_LOGIC ("IP Header size is: " << ip_header);
    delete temp_header;
    temp_header = new TcpHeader ();
    uint32_t tcp_header = temp_header->GetSerializedSize ();
    NS_LOG_LOGIC ("TCP Header size is: " << tcp_header);
    delete temp_header;
    uint32_t tcp_adu_size = mtu_bytes - 20 - (ip_header + tcp_header);
    NS_LOG_LOGIC ("TCP ADU size is: " << tcp_adu_size);

    double start_time = 0.01;
    double stop_time = start_time + duration;

    // Config::SetDefault ("ns3::TcpSocket::RcvBufSize", UintegerValue (1 << 21));
    // Config::SetDefault ("ns3::TcpSocket::SndBufSize", UintegerValue (1 << 21));
    // Config::SetDefault ("ns3::TcpSocketBase::Sack", BooleanValue (sack));
    Config::SetDefault ("ns3::TcpL4Protocol::RecoveryType", TypeIdValue (TypeId::LookupByName (recovery)));
    Config::SetDefault ("ns3::TcpSocket::InitialCwnd", UintegerValue (initialCwnd));
    Config::SetDefault ("ns3::TcpSocketBase::MinRto", TimeValue (Seconds (minRto)));
    Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (tcp_adu_size));

    TypeId tcpTid;
    NS_ABORT_MSG_UNLESS (TypeId::LookupByNameFailSafe (transport_prot, &tcpTid), "TypeId " << transport_prot << " not found");
    Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (TypeId::LookupByName (transport_prot)));

    Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable> ();
    uv->SetStream (50);
    RateErrorModel error_model;
    error_model.SetRandomVariable (uv);
    error_model.SetUnit (RateErrorModel::ERROR_UNIT_PACKET);
    error_model.SetRate (error_p);

    PointToPointHelper pointToPointRouter;
    pointToPointRouter.SetDeviceAttribute ("DataRate", StringValue (bandwidth));
    pointToPointRouter.SetChannelAttribute ("Delay", StringValue (delay));
    pointToPointRouter.SetDeviceAttribute ("ReceiveErrorModel", PointerValue (&error_model));

    PointToPointHelper pointToPointLeaf;
    pointToPointLeaf.SetDeviceAttribute ("DataRate", StringValue (access_bandwidth));
    pointToPointLeaf.SetChannelAttribute ("Delay", StringValue (access_delay));

    PointToPointDumbbellHelper d (nLeaf + 1, pointToPointLeaf,
                                  nLeaf + 1, pointToPointLeaf,
                                  pointToPointRouter);

    InternetStackHelper stack;
    d.InstallStack (stack);

    d.AssignIpv4Addresses (Ipv4AddressHelper ("10.1.1.0", "255.255.255.0"),
                           Ipv4AddressHelper ("10.2.1.0", "255.255.255.0"),
                           Ipv4AddressHelper ("10.3.1.0", "255.255.255.0"));

    DataRate access_b (access_bandwidth);
    DataRate bottle_b (bandwidth);
    Time access_d (access_delay);
    Time bottle_d (delay);

    uint32_t size = static_cast<uint32_t>((std::min (access_b, bottle_b).GetBitRate () / 8) *
        ((access_d + bottle_d) * 2).GetSeconds ());
    Config::SetDefault ("ns3::PfifoFastQueueDisc::MaxSize",
                        QueueSizeValue (QueueSize (QueueSizeUnit::PACKETS, size / mtu_bytes)));

    
    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    uint16_t port = 50000;
    Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny(), port));
    PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", sinkLocalAddress);
    ApplicationContainer sinkApp;

    for (uint16_t i = 0; i < nLeaf; i++)
    {
        sinkApp.Add (sinkHelper.Install (d.GetRight (i)));
    }

    PacketSinkHelper udpSink ("ns3::UdpSocketFactory", Address (InetSocketAddress (Ipv4Address::GetAny (), port)));
    sinkApp.Add (udpSink.Install (d.GetRight (nLeaf)));
    sinkApp.Start (Seconds (start_time));
    sinkApp.Stop (Seconds (stop_time));

    BulkSendHelper ftp ("ns3::TcpSocketFactory", Address ());
    ftp.SetAttribute ("MaxBytes", UintegerValue (int(data_mbytes * 1000000)));
    ftp.SetAttribute ("SendSize", UintegerValue (tcp_adu_size));

    ApplicationContainer sourceApp;

    for (uint16_t i = 0; i < nLeaf; i++)
    {
        AddressValue remoteAddress (InetSocketAddress (d.GetRightIpv4Address (i), port));
        ftp.SetAttribute ("Remote", remoteAddress);
        sourceApp = ftp.Install (d.GetLeft (i));
        sourceApp.Start (Seconds (start_time + i * 0.1));
        sourceApp.Stop (Seconds (stop_time -1));
    }

     AddressValue remoteAddress (InetSocketAddress (d.GetRightIpv4Address (nLeaf), port));
    OnOffHelper onOffHelper ("ns3::UdpSocketFactory", Address ());
    onOffHelper.SetConstantRate (DataRate ("1Mbps"));
    onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.01]"));
    onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=10]"));
    onOffHelper.SetAttribute ("Remote", remoteAddress);

    sourceApp = onOffHelper.Install (d.GetLeft (nLeaf));
    sourceApp.Start (Seconds (start_time));
    sourceApp.Stop (Seconds (stop_time - 1));
    
    std::ofstream ascii;
    Ptr<OutputStreamWrapper> ascii_wrap;
    ascii.open ((prefix_file_name + "-ascii").c_str ());
    ascii_wrap = new OutputStreamWrapper ((prefix_file_name + "-ascii").c_str (), std::ios::out);
    stack.EnableAsciiIpv4All (ascii_wrap);

    Simulator::Schedule (Seconds (0.00001), &TraceCwnd, prefix_file_name + "-cwnd.data");
    Simulator::Schedule (Seconds (0.00001), &TraceSsThresh, prefix_file_name + "-ssth.data");
    Simulator::Schedule (Seconds (0.00001), &TraceRtt, prefix_file_name + "-rtt.data");
    Simulator::Schedule (Seconds (0.00001), &TraceRto, prefix_file_name + "-rto.data");
    Simulator::Schedule (Seconds (0.00001), &TracePropRtt, prefix_file_name + "-rttprop.data");
    Simulator::Schedule (Seconds (0.00001), &TraceNextTx, prefix_file_name + "-next-tx.data");
    Simulator::Schedule (Seconds (0.00001), &TraceInflight, prefix_file_name + "-infilght.data");
    Simulator::Schedule (Seconds (0.1), &TraceNextRx, prefix_file_name + "-next-rx.data");

    pointToPointRouter.EnablePcapAll (prefix_file_name, true);

    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor = flowHelper.InstallAll();

    Simulator::Stop (Seconds (stop_time));
    Simulator::Run ();

    flowHelper.SerializeToXmlFile (prefix_file_name + ".flowmonitor", true, true);

    monitor->CheckForLostPackets ();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier ());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
        std::cout << "Flow " << i->first << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
        std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
        std::cout << "  TxOffered:  " << i->second.txBytes * 8.0 / 9.0 / 1000 / 1000  << " Mbps\n";
        std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
        std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
        std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / 9.0 / 1000 / 1000  << " Mbps\n";
    }

    Simulator::Destroy ();

    return 0;
}





