# IP-Sniffer:

```ruby
Compiler    : Delphi10 Seattle, 10.1 Berlin, 10.2 Tokyo, 10.3 Rio, 10.4 Sydney, 11 Alexandria, 12 Athens
Components  : WinApi.Winsock.pas
Discription : Network Monotoring
Last Update : 08/2025
License     : Freeware
```

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
