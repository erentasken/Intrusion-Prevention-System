package model

type Detection struct {
	Method     string `json:"Method"`
	Protocol   string `json:"Protocol"`
	AttackerIP string `json:"Attacker_ip"`
	TargetPort string `json:"Target_port"`
	Message    string `json:"Message"`
}
