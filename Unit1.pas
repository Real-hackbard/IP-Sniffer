unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  ComCtrls, Winsock, StdCtrls, ExtCtrls, XPMan, Menus, ClipBrd;

const
  MAX_PACKET_SIZE = $10000;
  SIO_RCVALL      = $98000001;

type
  TForm1 = class(TForm)
    ListView1: TListView;
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
    Memo1: TMemo;
    SaveDialog1: TSaveDialog;
    N1: TMenuItem;
    N2: TMenuItem;
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

implementation

{$R *.DFM}
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
  hdr: PIPHeader;
begin
  flag := 1;
  WSAStartup(MAKEWORD(2,2), wsadata);
  s := socket(AF_INET, SOCK_RAW, IPPROTO_IP);
  gethostname(name, sizeof(name));
  phe := gethostbyname(name);
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

        {
        case hdr.iph_protocol of
          IPPROTO_IP:   SubItems.Add('IP');
          IPPROTO_TCP:  SubItems.Add('TCP');
          IPPROTO_UDP:  SubItems.Add('UDP');
          IPPROTO_ICMP: SubItems.Add('ICMP');
          IPPROTO_IGMP: SubItems.Add('IGMP');
          IPPROTO_GGP: SubItems.Add('GGP');
          IPPROTO_PUP: SubItems.Add('PUP');
          IPPROTO_IDP: SubItems.Add('IDP');
          IPPROTO_ND: SubItems.Add('ND');
          IPPROTO_RAW:  SubItems.Add('RAW');
        else
          SubItems.Add('Socket Error!')
        end;
        }

        if Form1.CheckBox1.Checked = true then begin
          if hdr.iph_protocol = 0 then SubItems.Add('IP');
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

      end;
  until false;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  ThID: Cardinal;
begin
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

procedure TForm1.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  while not TerminateThread(hThread,0) do
    Sleep(100);
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
  Button1.Enabled := false;
  Button2.Enabled := true;
  C1.Enabled := true;
  C2.Enabled := true;
  S3.Enabled := true;


  while not TerminateThread(hThread,0) do
  Sleep(10);
end;

procedure TForm1.Button2Click(Sender: TObject);
var
  ThID: Cardinal;
begin
  hThread := CreateThread(nil,0, @ListenThread, ListView1,0,ThID);
 if hThread=0 then ShowMessage(SysErrorMessage(GetLastError));
 Button1.Enabled := true;
 Button2.Enabled := false;
 C1.Enabled := false;
 C2.Enabled := false;
 S3.Enabled := false;
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
      Memo1.Lines.Add('Protocol : ' + ListView1.Items[I].SubItems[0] + ' | '  + 'Local : ' + ListView1.Items[I].SubItems[1]
       + ' | '  + 'Destination : ' + ListView1.Items[I].SubItems[2] + ' | '  + 'Port : ' + ListView1.Items[I].SubItems[3]
        + ' | '  + 'TTL : ' + ListView1.Items[I].SubItems[4]);
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
