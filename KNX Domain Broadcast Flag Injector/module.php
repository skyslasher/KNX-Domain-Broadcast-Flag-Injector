<?php
    class KNXDomainBroadcastFlagInjector extends IPSModule
    {
        public function Create()
        {
            //Never delete this line!
            parent::Create();

            // UDP socket
            $this->RequireParent("{82347F20-F541-41E1-AC5B-A636FD3AE2D8}");

            // UDP socket configuration
            $this->RegisterPropertyString("BindIP", '172.17.31.180');
            $this->RegisterPropertyInteger("BindPort", 0);
            $this->RegisterPropertyBoolean("EnableBroadcast", false);
            $this->RegisterPropertyBoolean("EnableLoopback", false);
            $this->RegisterPropertyBoolean("EnableReuseAddress", false);
            $this->RegisterPropertyString("Host", '');
            $this->RegisterPropertyBoolean("Open", false);
            $this->RegisterPropertyInteger("Port", 0);

            // UDP socket connected
            $this->RegisterMessage($this->InstanceID, FM_CONNECT);
            // UDP socket configuration changed
            $this->RegisterMessage($this->InstanceID, IM_CHANGESETTINGS);
        }

        private function GetParent()
        {
            $InstanceInfo = IPS_GetInstance($this->InstanceID);
            if (array_key_exists('ConnectionID', $InstanceInfo)) {
                return $InstanceInfo['ConnectionID'];
            }
            return 0;
        }

        private function ApplyConfigurationFromParent()
        {
            $InstanceID = $this->InstanceID;
            $ParentID = $this->GetParent();
            if ((0 != $ParentID) && IPS_InstanceExists($ParentID)) {
                IPS_SetConfiguration($InstanceID, IPS_GetConfiguration($ParentID));
            }
        }

        public function ForwardData($JSONString)
        {
            $data = json_decode($JSONString);
            if ("{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}" == $data->DataID) {
                $dataBuffer = utf8_decode($data->Buffer);
                // cEMI messages start at byte offset 10
                if (10 < strlen($dataBuffer)) {
                    // UDP packet offset to cEMI message
                    $offset = 10;
                    $messagecode = ord($dataBuffer[$offset]);
                    // cEMI message?
                    if ((0x29 == $messagecode) || (0x2e == $messagecode) || (0x11 == $messagecode)) {
                        // additional length set?
                        if (0x00 != ord($dataBuffer[1 + $offset])) {
                            $offset++;
                        }
                        $cf1 = ord($dataBuffer[2 + $offset]);
                        if (0 == (0b00010000 & $cf1)) {
                            // system broadcast -> modify to domain broadcast
                            $cf1 |= 0b00010000;
                            $dataBuffer[2 + $offset] = chr($cf1);
                            $data->Buffer = utf8_encode($dataBuffer);
                            $JSONString = json_encode($data);
                        }
                    }
                }
            }
            $this->SendDataToParent($JSONString);
        }

        public function ReceiveData($JSONString)
        {
            $this->SendDataToChildren($JSONString);
        }

        public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
        {
            switch ($Message) {
                case FM_CONNECT:
                    if ($this->InstanceID == $SenderID) {
                        $this->ApplyConfigurationFromParent();
                    }
                break;
                case IM_CHANGESETTINGS:
                    if ($this->GetParent() == $SenderID) {
                        $this->ApplyConfigurationFromParent();
                    }
                break;
            }
        }
    }
