package service

import (
	"encoding/csv"
	"os"
	"strconv"
)

func WriteToCSV(filename string, features *FeatureAnalyzer) error {

	// Create datasets directory if it is not exists
	if _, err := os.Stat("datasets"); os.IsNotExist(err) {
		os.Mkdir("datasets", 0755)
	}

	filename = "datasets/" + filename

	csvName := filename + ".csv"

	file, err := os.OpenFile(csvName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fileInfo, _ := file.Stat()
	if fileInfo.Size() == 0 {
		// header := []string{
		// 	"Destination Port", "Flow Duration",

		// 	"Total Fwd Packets", "Total Backward Packets",
		// 	"Total Length of Fwd Packets", "Total Length of Bwd Packets",

		// 	"Fwd Packet Length Max", "Fwd Packet Length Min",
		// 	"Fwd Packet Length Mean", "Fwd Packet Length Std",

		// 	"Bwd Packet Length Max", "Bwd Packet Length Min",
		// 	"Bwd Packet Length Mean", "Bwd Packet Length Std",

		// 	"Flow Bytes/s", "Flow Packets/s",

		// 	"Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
		// 	"Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
		// 	"Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",

		// 	"Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",

		// 	"Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
		// 	"Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",

		// 	"FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
		// 	"CWE Flag Count", "ECE Flag Count",

		// 	"Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
		// 	"Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",

		// 	"Subflow Fwd Packets", "Subflow Fwd Bytes",
		// 	"Subflow Bwd Packets", "Subflow Bwd Bytes",

		// 	"Active Mean", "Idle Mean",
		// }

		// header := []string{"Flow Duration", "Total Fwd Packets", "Total Backward Packets",
		// 	"Total Length of Fwd Packets", "Total Length of Bwd Packets",
		// 	"Fwd Packet Length Max", "Fwd Packet Length Min",
		// 	"Fwd Packet Length Mean", "Fwd Packet Length Std",
		// 	"Bwd Packet Length Max", "Bwd Packet Length Min",
		// 	"Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
		// 	"Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
		// 	"Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
		// 	"Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
		// 	"Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd Header Length",
		// 	"Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
		// 	"Min Packet Length", "Max Packet Length", "Packet Length Mean",
		// 	"Packet Length Std", "FIN Flag Count", "SYN Flag Count",
		// 	"RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
		// 	"Active Mean", "Idle Mean"}

		header := []string{"Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
			"Total Length of Fwd Packets", "Total Length of Bwd Packets",
			"Fwd Packet Length Mean", "Fwd Packet Length Std",
			"Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
			"Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
			"Fwd IAT Mean", "Fwd IAT Std",
			"Bwd IAT Mean", "Bwd IAT Std",

			"Fwd Packets/s", "Bwd Packets/s",

			"Packet Length Mean", "Packet Length Std",

			"FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",

			"Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
			"Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",

			"Subflow Fwd Packets", "Subflow Fwd Bytes",
			"Subflow Bwd Packets", "Subflow Bwd Bytes",

			"Active Mean", "Idle Mean"}

		writer.Write(header)
	}

	data := []string{
		strconv.FormatUint((features.features.Protocol), 10),
		// strconv.FormatUint(features.features.DestinationPort, 10),
		strconv.FormatFloat(features.features.FlowDuration, 'f', 3, 64),

		strconv.FormatUint(features.features.TotalFwdPackets, 10),
		strconv.FormatUint(features.features.TotalBwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthFwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthBwdPackets, 10),

		// strconv.FormatUint(features.features.FwdPacketLengthMax, 10),
		// strconv.FormatUint(features.features.FwdPacketLengthMin, 10),
		strconv.FormatFloat(features.features.FwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.FwdPacketLengthStd, 'f', 3, 64),

		// strconv.FormatUint(features.features.BwdPacketLengthMax, 10),
		// strconv.FormatUint(features.features.BwdPacketLengthMin, 10),
		strconv.FormatFloat(features.features.BwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketLengthStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.FlowBytesPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.FlowPacketsPerSec, 'f', 3, 64),

		strconv.FormatFloat(features.features.IATFeatures.FlowIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.FlowIATStd, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.FlowIATMax, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.FlowIATMin, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATTotal, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATStd, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMax, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMin, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATTotal, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATStd, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMax, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMin, 'f', 3, 64),

		// strconv.FormatUint(features.features.FlagFeatures.FwdPSHFlags, 10),
		// strconv.FormatUint(features.features.FlagFeatures.BwdPSHFlags, 10),
		// strconv.FormatUint(features.features.FlagFeatures.FwdURGFlags, 10),
		// strconv.FormatUint(features.features.FlagFeatures.BwdURGFlags, 10),

		// strconv.FormatUint(features.features.FwdHeaderLength, 10),
		// strconv.FormatUint(features.features.BwdHeaderLength, 10),
		strconv.FormatFloat(features.features.FwdPacketsPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketsPerSec, 'f', 3, 64),

		// strconv.FormatUint(features.features.MinPacketLength, 10),
		// strconv.FormatUint(features.features.MaxPacketLength, 10),
		strconv.FormatFloat(features.features.PacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.PacketLengthStd, 'f', 3, 64),

		strconv.FormatUint(features.features.FlagFeatures.FinFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.SynFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.RstFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.PshFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.AckFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.UrgFlagCount, 10),

		// strconv.FormatUint(features.features.FlagFeatures.CweFlagCount, 10),
		// strconv.FormatUint(features.features.FlagFeatures.EceFlagCount, 10),

		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgPacketsBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgPacketsBulk, 'f', 3, 64),

		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdBytes, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdBytes, 10),

		strconv.FormatFloat(features.features.ActiveMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IdleMean, 'f', 3, 64),
	}
	writer.Write(data)

	return nil
}

func returnDataIntoString(features *FeatureAnalyzer) []string {
	return []string{
		strconv.FormatUint((features.features.Protocol), 10),
		strconv.FormatFloat(features.features.FlowDuration, 'f', 3, 64),

		strconv.FormatUint(features.features.TotalFwdPackets, 10),
		strconv.FormatUint(features.features.TotalBwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthFwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthBwdPackets, 10),

		strconv.FormatFloat(features.features.FwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.FwdPacketLengthStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.BwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketLengthStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.FlowBytesPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.FlowPacketsPerSec, 'f', 3, 64),

		strconv.FormatFloat(features.features.IATFeatures.FlowIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.FlowIATStd, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATStd, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.FwdPacketsPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketsPerSec, 'f', 3, 64),

		strconv.FormatFloat(features.features.PacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.PacketLengthStd, 'f', 3, 64),

		strconv.FormatUint(features.features.FlagFeatures.FinFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.SynFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.RstFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.PshFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.AckFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.UrgFlagCount, 10),

		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgPacketsBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgPacketsBulk, 'f', 3, 64),

		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdBytes, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdBytes, 10),

		strconv.FormatFloat(features.features.ActiveMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IdleMean, 'f', 3, 64),
	}
}
