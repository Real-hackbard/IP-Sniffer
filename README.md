# IP-Sniffer:

</br>

![Compiler](https://github.com/user-attachments/assets/a916143d-3f1b-4e1f-b1e0-1067ef9e0401) &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: ![10 Seattle](https://github.com/user-attachments/assets/c70b7f21-688a-4239-87c9-9a03a8ff25ab) ![10 1 Berlin](https://github.com/user-attachments/assets/bdcd48fc-9f09-4830-b82e-d38c20492362) ![10 2 Tokyo](https://github.com/user-attachments/assets/5bdb9f86-7f44-4f7e-aed2-dd08de170bd5) ![10 3 Rio](https://github.com/user-attachments/assets/e7d09817-54b6-4d71-a373-22ee179cd49c)   
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;![10 4 Sydney](https://github.com/user-attachments/assets/e75342ca-1e24-4a7e-8fe3-ce22f307d881) ![11 Alexandria](https://github.com/user-attachments/assets/64f150d0-286a-4edd-acab-9f77f92d68ad) ![12 Athens](https://github.com/user-attachments/assets/59700807-6abf-4e6d-9439-5dc70fc0ceca)  
![Components](https://github.com/user-attachments/assets/d6a7a7a4-f10e-4df1-9c4f-b4a1a8db7f0e) : ![None](https://github.com/user-attachments/assets/30ebe930-c928-4aaf-a8e1-5f68ec1ff349)  
![Discription](https://github.com/user-attachments/assets/4a778202-1072-463a-bfa3-842226e300af) &nbsp;&nbsp;: ![IP Sniffer](https://github.com/user-attachments/assets/691981c4-0f1f-4e25-95f3-8ebdd0f962a1)  
![Last Update](https://github.com/user-attachments/assets/e1d05f21-2a01-4ecf-94f3-b7bdff4d44dd) &nbsp;: ![102025](https://github.com/user-attachments/assets/62cea8cc-bd7d-49bd-b920-5590016735c0)  
![License](https://github.com/user-attachments/assets/ff71a38b-8813-4a79-8774-09a2f3893b48) &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: ![Freeware](https://github.com/user-attachments/assets/1fea2bbf-b296-4152-badd-e1cdae115c43)

</br>

An IP sniffer is a type of monitoring tool that monitors and analyzes network traffic. It operates at a low level of the network stack, allowing it to intercept and examine data packets as they travel through a network. These tools are often referred to as "packet sniffer" or "[network sniffer](https://en.wikipedia.org/wiki/Sniffer_(protocol_analyzer))."

An IP sniffer intercepts all or selected data packets passing through a network. Each packet contains various information, including the source and destination IP addresses, protocols, and possibly the data content.

</br>

### Update:
* New VCL Library
* Sniff Hosts Domains

</br>

![IP Sniffer](https://github.com/user-attachments/assets/9f234bbc-8659-48cb-85a0-1a3fa077d4b1)


</br>

After capturing the packets, the sniffer can analyze them to learn details about network activity, such as which devices are communicating with each other, what type of data is being transferred, and which IP addresses are involved.

IT administrators use sniffers to diagnose network problems, such as identifying bottlenecks, misconfigurations, or unauthorized devices. Security professionals use sniffers to detect suspicious activity, such as potential intrusions or data exfiltration. Developers and researchers use sniffers to investigate the functionality of various network and [internet protocols](https://en.wikipedia.org/wiki/Internet_protocol_suite) or to debug network applications.

</br>

### Sniffed Protocols:

| [Protocol Number](https://de.wikipedia.org/wiki/Protokoll_(IP)) | Protocol                                 |
| :-------------: | :--------------------------------------: |
| 1               | [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) (Internet Control Message Protocol) |
| 2               | [IGMP](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol) (Internet Group Management Protocol)   |
| 3               | [GGP](https://en.wikipedia.org/wiki/Gateway-to-Gateway_Protocol) (Gateway-to-Gateway)   |
| 4               | [IP](https://en.wikipedia.org/wiki/Internet_Protocol) (IP in IP (encapsulation))   |
| 6               | [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) (Transmission Control Protocol)   |
| 12              | [PUP](https://en.wikipedia.org/wiki/PARC_Universal_Packet) PARC Universal Packet (PUP)   |
| 17              | [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) (User Datagram Protocol)   |
| 22              | [IDP](https://en.wikipedia.org/wiki/Identity_provider) XNS-IDP (XEROX NS IDP)   |
| 77              | [NDP](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol) SUN-ND (SUN ND PROTOCOL-Temporary)   |
| 255             | RAW (Reserved)   |

</br>

### Add Protocols:
To integrate additional protocols, the protocol numbers and the name of the protocol must be added in this part of the code.

```pascal
repeat
     if Form1.Button1.Enabled = false then Exit;
     count := recv(s, Buffer, sizeof(Buffer), 0);
      if (count >= sizeof(TIPHeader)) then
      with LV.Items.Add do
      begin
        hdr := @Buffer;
        Caption:= TimeToStr(Time);

        case hdr.iph_protocol of
          IPPROTO_IP: begin
                      a := a + 1;
                      Form1.CheckBox1.Caption := 'IP (' + IntToStr(a) + ')';
                      end;

          IPPROTO_TCP:begin
                      b := b + 1;
                      Form1.CheckBox2.Caption := 'TCP (' + IntToStr(b) + ')';
                      end;

          IPPROTO_UDP:begin
                      c := c + 1;
                      Form1.CheckBox3.Caption := 'UDP (' + IntToStr(c) + ')';
                      end;

          IPPROTO_ICMP: begin
                        d := d + 1;
                        Form1.CheckBox4.Caption := 'ICMP (' + IntToStr(d) + ')';
                        end;

          IPPROTO_IGMP: begin
                        e := e + 1;
                        Form1.CheckBox4.Caption := 'IGMP (' + IntToStr(e) + ')';
                        end;

          IPPROTO_GGP: begin
                        f := f + 1;
                        Form1.CheckBox5.Caption := 'PUP (' + IntToStr(f) + ')';
                        end;

          IPPROTO_PUP: begin
                        g := g + 1;
                        Form1.CheckBox6.Caption := 'IDP (' + IntToStr(g) + ')';
                        end;

          IPPROTO_IDP: begin
                        h := h + 1;
                        Form1.CheckBox7.Caption := 'GGP (' + IntToStr(h) + ')';
                        end;
          IPPROTO_ND: begin
                      j := j + 1;
                      Form1.CheckBox8.Caption := 'NDP (' + IntToStr(j) + ')';
                      end;
          IPPROTO_RAW:  begin
                        k := k + 1;
                        Form1.CheckBox9.Caption := 'RAW (' + IntToStr(k) + ')';
                        end;
        //else
          //SubItems.Add('Socket Error!')  // Intigrate when you want!
        end;


        if Form1.CheckBox1.Checked = true then begin
          if hdr.iph_protocol = 4 then SubItems.Add('IP');
        end;

        if Form1.CheckBox2.Checked = true then begin
          if hdr.iph_protocol = 6 then SubItems.Add('TCP');
        end;

        if Form1.CheckBox3.Checked = true then begin
          if hdr.iph_protocol = 17 then SubItems.Add('UDP');
        end;

        if Form1.CheckBox4.Checked = true then begin
          if hdr.iph_protocol = 1 then SubItems.Add('ICMP');
        end;

        if Form1.CheckBox5.Checked = true then begin
          if hdr.iph_protocol = 2 then SubItems.Add('IGMP');
        end;

        if Form1.CheckBox6.Checked = true then begin
          if hdr.iph_protocol = 12 then SubItems.Add('PUP');
        end;

        if Form1.CheckBox7.Checked = true then begin
          if hdr.iph_protocol = 22 then SubItems.Add('IDP');
        end;

        if Form1.CheckBox8.Checked = true then begin
          if hdr.iph_protocol = 3 then SubItems.Add('GGP');
        end;

        if Form1.CheckBox9.Checked = true then begin
          if hdr.iph_protocol = 77 then SubItems.Add('NDP');
        end;

        if Form1.CheckBox10.Checked = true then begin
          if hdr.iph_protocol = 255 then SubItems.Add('RAW');
        end;

        try
          // Winsock Library
          sa1.s_addr := hdr.iph_src;
          SubItems.Add(inet_ntoa(sa1));
          sa1.s_addr := hdr.iph_dest;
          SubItems.Add(inet_ntoa(sa1));
          lowbyte := hdr.iph_length shr 8;
          hibyte := hdr.iph_length shl 8;
          hibyte := hibyte + lowbyte;
          SubItems.Add(IntToStr(hibyte));
          SubItems.Add(IntToStr(hdr.iph_ttl));
          SubItems.Add(IntToStr(hdr.iph_xsum));
          SubItems.Add(IntToStr(hdr.iph_length));
          SubItems.Add(IntToStr(hdr.iph_offset));
          SubItems.Add(IntToStr(hdr.iph_tos));
          SubItems.Add(IntToStr(hdr.iph_id));
          SubItems.Add(IntToStr(hdr.iph_verlen));
          SubItems.Add(IntToStr(sizeof(Buffer)));

          if SubItems.Text = '' then begin
          Form1.ListView1.Items.Delete(Form1.ListView1.ItemIndex)
          end;
        except
        end;

      Form1.StatusBar1.Panels[1].Text := IntToStr(Form1.ListView1.Items.Count);
      end;
  until false;
```
