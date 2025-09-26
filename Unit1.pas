unit Unit1;

interface

uses
  WinApi.Windows, WinApi.Messages, System.SysUtils, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.StdCtrls,
  WinApi.Winsock, Vcl.ExtCtrls, Vcl.Menus, ClipBrd;

const
  MAX_PACKET_SIZE = $10000;
  SIO_RCVALL      = $98000001;

type
  TForm1 = class(TForm)
    StatusBar1: TStatusBar;
    Panel1: TPanel;
    Button1: TButton;
    Button2: TButton;
    CheckBox1: TCheckBox;
    CheckBox2: TCheckBox;
    CheckBox3: TCheckBox;
    CheckBox4: TCheckBox;
    CheckBox5: TCheckBox;
    CheckBox6: TCheckBox;
    CheckBox7: TCheckBox;
    CheckBox8: TCheckBox;
    CheckBox9: TCheckBox;
    CheckBox10: TCheckBox;
    PopupMenu1: TPopupMenu;
    S1: TMenuItem;
    S2: TMenuItem;
    C1: TMenuItem;
    C2: TMenuItem;
    S3: TMenuItem;
    SaveDialog1: TSaveDialog;
    N1: TMenuItem;
    N2: TMenuItem;
    Button3: TButton;
    Memo2: TMemo;
    ListView1: TListView;
    Memo1: TMemo;
    Splitter1: TSplitter;
    Bevel1: TBevel;
    Label1: TLabel;
    Label2: TLabel;
    CheckBox11: TCheckBox;
    CheckBox12: TCheckBox;
    CheckBox13: TCheckBox;
    CheckBox14: TCheckBox;
    CheckBox15: TCheckBox;
    Bevel2: TBevel;
    Bevel3: TBevel;
    Panel2: TPanel;
    Button4: TButton;
    procedure FormCreate(Sender: TObject);
    procedure ListView1Change(Sender: TObject; Item: TListItem;
      Change: TItemChange);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure CheckBox1Click(Sender: TObject);
    procedure CheckBox2Click(Sender: TObject);
    procedure CheckBox3Click(Sender: TObject);
    procedure CheckBox4Click(Sender: TObject);
    procedure CheckBox5Click(Sender: TObject);
    procedure CheckBox6Click(Sender: TObject);
    procedure CheckBox7Click(Sender: TObject);
    procedure CheckBox8Click(Sender: TObject);
    procedure CheckBox9Click(Sender: TObject);
    procedure CheckBox10Click(Sender: TObject);
    procedure C1Click(Sender: TObject);
    procedure S1Click(Sender: TObject);
    procedure S2Click(Sender: TObject);
    procedure C2Click(Sender: TObject);
    procedure S3Click(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure ListView1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

type
  USHORT = Word;
  TIPHeader = record
    iph_verlen:   UCHAR;
    iph_tos:      UCHAR;
    iph_length:   USHORT;
    iph_id:       USHORT;
    iph_offset:   USHORT;
    iph_ttl:      UCHAR;
    iph_protocol: UCHAR;
    iph_xsum:     USHORT;
    iph_src:      ULONG;
    iph_dest:     ULONG;
  end;
  PIPHeader = ^TIPHeader;

var
  Form1: TForm1;
  Buffer: array [0..MAX_PACKET_SIZE] of Char;
  flag: Integer;
  hThread: Cardinal;
  stop : Boolean;

implementation

{$R *.DFM}
procedure Selectline(memo:TMemo;line:integer);
begin
  memo.SelStart := memo.Perform(EM_LINEINDEX, line-1, 0);
  memo.Perform(EM_SCROLLCARET, 0, 0);
  memo.sellength:=length(Memo.lines.strings[line-1]);
  memo.SetFocus;
end;

function IPAddrToName(IPAddr: Ansistring): string;
var SockAddrIn: TSockAddrIn;HostEnt: PHostEnt;WSAData: TWSAData;
begin
  WSAStartup($101, WSAData);
  SockAddrIn.sin_addr.s_addr := inet_addr(PAnsiChar(IPAddr));
  HostEnt := gethostbyaddr(@SockAddrIn.sin_addr.S_addr, 4, AF_INET);

  if HostEnt <> nil then
    Result := StrPas(Hostent^.h_name)
  else
    Result := '';
end;

procedure ListenThread(LV: TListView); stdcall;
var
  lowbyte, hibyte: USHORT;
  wsadata: TWSAData;
  s: TSocket;
  name: array [0..128]of Char;
  phe: PHostent;
  sa: TSockAddrIn;
  sa1: TInAddr;
  count: Integer;
  a, b, c, d, e, f, g, h, j, k : integer; // dont use "i"
  hdr: PIPHeader;
begin
  {$R-}   // Important area check
  a := 0;
  b := 0;
  c := 0;
  d := 0;
  e := 0;
  f := 0;
  g := 0;
  h := 0;
  j := 0;
  k := 0;
  flag := 1;
  WSAStartup(MAKEWORD(2,2), wsadata);
  s := socket(AF_INET, SOCK_RAW, IPPROTO_IP);
  gethostname(@name, sizeof(name));
  phe := gethostbyname(@name);
  ZeroMemory(@sa, sizeof(sa));
  sa.sin_family := AF_INET;
  sa.sin_addr.s_addr := cardinal(pointer(phe^.h_addr_list^)^);
  bind(s, sa, sizeof(TSockaddr));
  ioctlsocket(s, SIO_RCVALL, flag);
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
  {$R-}
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  ThID: Cardinal;
begin
 Panel1.DoubleBuffered := true;
 Panel2.DoubleBuffered := true;
 hThread := CreateThread(nil,0, @ListenThread, ListView1,0, ThID);
 if hThread = 0 then
  ShowMessage(SysErrorMessage(GetLastError));
end;

procedure TForm1.ListView1Change(Sender: TObject; Item: TListItem;
  Change: TItemChange);
begin
  if Button2.Enabled = false then
  ListView1.Scroll(0,Item.Position.y);
end;

procedure TForm1.ListView1Click(Sender: TObject);
var
  itemp: Integer;
  item: TListItem;
begin
  if Button2.Enabled = false then Exit;

  try
  with Memo2 do
    begin
      itemp := ListView1.Selected.Index;
      SelStart := Perform(EM_LINEINDEX, itemp, 0) + 3;
        Perform(EM_SCROLLCARET, 0, 0);
      selectLine(Memo2, itemp);

      item := ListView1.Selected;
      if item <> nil then
      begin
       StatusBar1.Panels[5].Text := item.SubItems[2]
      end;

    end;
  except
  end;
end;

procedure TForm1.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  while not TerminateThread(hThread,0) do
    Sleep(50);
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
  Button1.Enabled := false;
  Button3.Enabled := true;
  C1.Enabled := true;
  C2.Enabled := true;
  S3.Enabled := true;

  Screen.Cursor := crHourGlass;
  StatusBar1.Panels[3].Text := 'Sniffer stop, please wait..';

  try
    while not TerminateThread(hThread,0) do begin
    StatusBar1.Panels[3].Text := 'Scanning stop.';
    Sleep(1000);
    end;
  except
  end;

  //ListView1.Items.Delete(Form1.ListView1.ItemIndex);
  Button2.Enabled := true;
  //Application.ProcessMessages;
  Screen.Cursor := crDefault;
end;

procedure TForm1.Button2Click(Sender: TObject);
var
  ThID: Cardinal;
begin
   Button1.Enabled := true;
   Button2.Enabled := false;
   Button3.Enabled := false;
   C1.Enabled := false;
   C2.Enabled := false;
   S3.Enabled := false;
   ListView1.Clear;
   StatusBar1.Panels[3].Text := 'Scanning IP..';

   hThread := CreateThread(nil,0, @ListenThread, ListView1,0,ThID);
   if hThread=0 then ShowMessage(SysErrorMessage(GetLastError));
end;

procedure TForm1.Button3Click(Sender: TObject);
var i : integer;
    protocol, port, bytes, ttl, length : string;
begin
  if ListView1.Items.Count <= 0 then begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  Screen.Cursor := crHourGlass;
  stop := false;
  Button4.Enabled := true;
  Button3.Enabled := false;
  Memo2.Clear;
  Memo2.Enabled := false;
  StatusBar1.Panels[3].Text := 'Scanning Host Domains, please wait..';
  for i := 0 to ListView1.Items.Count -1 do begin
     protocol := '';

       if CheckBox11.Checked = true then begin
       protocol := ListView1.Items[i].SubItems[0]+ ' | ';
       end;

       if CheckBox12.Checked = true then begin
       port := 'Port : ' + ListView1.Items[i].SubItems[3] + ' | ';
       end;

       if CheckBox13.Checked = true then begin
       bytes := 'Bytes : ' + ListView1.Items[i].SubItems[5] + ' | ';
       end;

       if CheckBox14.Checked = true then begin
       bytes := 'TTL : ' + ListView1.Items[i].SubItems[4] + ' | ';
       end;

       if CheckBox15.Checked = true then begin
       bytes := 'Length : ' + ListView1.Items[i].SubItems[6] + ' | ';
       end;

        try
          begin
            if IPAddrToName(ListView1.items[i].SubItems[2]) = '' then begin
            Memo2.Lines.Add(ListView1.Items[i].SubItems[2] +
                            ' | => | '  + ' (Unknown) or (Socket Error).');
            end else begin
            Memo2.Lines.Add(protocol + port + bytes + Length +
                            ListView1.Items[i].SubItems[2] +
                            ' | Domain =>     '  +
                            IPAddrToName(ListView1.items[i].SubItems[2]));
            end;
          end;
        except
        end;

      Application.ProcessMessages;
      if stop = true then begin
        StatusBar1.Panels[3].Text := 'Scanning abort!';
        Memo2.Enabled := true;
        Screen.Cursor := crDefault;
        Exit;
      end;
      Screen.Cursor := crDefault;
 end;

 StatusBar1.Panels[3].Text := 'Scanning done!';
 Button3.Enabled := true;
 Button4.Enabled := false;
 Memo2.Enabled := true;
end;

procedure TForm1.Button4Click(Sender: TObject);
begin
  stop := true;
  Button3.Enabled := true;
  Button4.Enabled := false;
end;

procedure TForm1.CheckBox1Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox2Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox3Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox4Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox5Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox6Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox7Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox8Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox9Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.CheckBox10Click(Sender: TObject);
begin
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false) and
     (Form1.CheckBox7.Checked = false) and (Form1.CheckBox8.Checked = false) and
     (Form1.CheckBox9.Checked = false) and (Form1.CheckBox10.Checked = false)
  then begin
  Form1.Button1.Click;
  end;
end;

procedure TForm1.C1Click(Sender: TObject);
begin
  ListView1.Clear;
  Memo2.Clear;
end;

procedure TForm1.S1Click(Sender: TObject);
begin
  Button2.Click;
end;

procedure TForm1.S2Click(Sender: TObject);
begin
  Button1.Click;
end;

procedure TForm1.C2Click(Sender: TObject);
var  item: TListItem; s : string;
begin
  item := ListView1.Selected;
  if item <> nil then
  begin
   s := item.SubItems[2]; Clipboard.AsText := s;
  end;
end;

procedure TForm1.S3Click(Sender: TObject);
var  i : integer;
begin
   Memo1.Clear;
    for I := 0 to ListView1.Items.Count - 1 do
    begin
      Memo1.Lines.Add('Time : ' + ListView1.Items[i].Caption) ;
      Memo1.Lines.Add('Protocol : ' + ListView1.Items[I].SubItems[0] +
                      ' | '  + 'Local : ' + ListView1.Items[I].SubItems[1] +
                      ' | '  + 'Destination : ' + ListView1.Items[I].SubItems[2] +
                      ' | '  + 'Port : ' + ListView1.Items[I].SubItems[3] +
                      ' | '  + 'TTL : ' + ListView1.Items[I].SubItems[4]);
      Memo1.Lines.Add('');
    end;

  if SaveDialog1.Execute then begin
  Memo1.Lines.SaveToFile(SaveDialog1.FileName + '.txt');
  end;
end;

procedure TForm1.FormShow(Sender: TObject);
begin
  Button2.OnClick(sender);
end;

end.
