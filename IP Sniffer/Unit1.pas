unit Unit1;

interface

uses
  WinApi.Windows, WinApi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.StdCtrls, WinApi.Winsock, Vcl.ExtCtrls, Vcl.Menus,
  Vcl.ClipBrd, System.ImageList, Vcl.ImgList, WinApi.ActiveX,
  System.Win.ComObj, Vcl.Samples.Spin, System.IniFiles, WinApi.WinInet;

const
  MAX_PACKET_SIZE = $10000;
  SIO_RCVALL      = $98000001;

type
  TForm1 = class(TForm)
    StatusBar1: TStatusBar;
    Panel1: TPanel;
    Panel2: TPanel;
    Label1: TLabel;
    Label2: TLabel;
    Bevel2: TBevel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
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
    Button3: TButton;
    CheckBox11: TCheckBox;
    CheckBox12: TCheckBox;
    CheckBox13: TCheckBox;
    CheckBox14: TCheckBox;
    CheckBox15: TCheckBox;
    Button4: TButton;
    SpinEdit1: TSpinEdit;
    Button5: TButton;
    ComboBox1: TComboBox;
    Panel3: TPanel;
    Splitter1: TSplitter;
    ListView1: TListView;
    Memo1: TMemo;
    Panel4: TPanel;
    Memo2: TMemo;
    HeaderControl1: THeaderControl;
    PopupMenu1: TPopupMenu;
    S1: TMenuItem;
    S2: TMenuItem;
    Scanhosts1: TMenuItem;
    N1: TMenuItem;
    C1: TMenuItem;
    C2: TMenuItem;
    N2: TMenuItem;
    Gethost1: TMenuItem;
    Ping1: TMenuItem;
    Whois1: TMenuItem;
    Locations1: TMenuItem;
    Country1: TMenuItem;
    City1: TMenuItem;
    N5: TMenuItem;
    Location1: TMenuItem;
    myLocation1: TMenuItem;
    N3: TMenuItem;
    S3: TMenuItem;
    Panel: TMenuItem;
    View1: TMenuItem;
    Protocol1: TMenuItem;
    Port1: TMenuItem;
    TL1: TMenuItem;
    xSum1: TMenuItem;
    Length1: TMenuItem;
    Offset1: TMenuItem;
    Os1: TMenuItem;
    ID1: TMenuItem;
    Ver1: TMenuItem;
    Buffer1: TMenuItem;
    SaveDialog1: TSaveDialog;
    ImageList1: TImageList;
    Label7: TLabel;
    Button6: TButton;
    Priority1: TMenuItem;
    Idle1: TMenuItem;
    Lowest1: TMenuItem;
    Lower1: TMenuItem;
    Normal1: TMenuItem;
    Higher1: TMenuItem;
    Highest1: TMenuItem;
    imeCritical1: TMenuItem;
    N6: TMenuItem;
    Options1: TMenuItem;
    Label6: TLabel;
    CheckBox16: TCheckBox;
    CheckBox17: TCheckBox;
    FindDialog1: TFindDialog;
    Button7: TButton;
    coordinates1: TMenuItem;
    OwnerCompany1: TMenuItem;
    PostalNumber1: TMenuItem;
    Region1: TMenuItem;
    CheckBox18: TCheckBox;
    Button8: TButton;
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
    procedure Panel3Click(Sender: TObject);
    procedure Gethost1Click(Sender: TObject);
    procedure Ping1Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Location1Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure Protocol1Click(Sender: TObject);
    procedure Port1Click(Sender: TObject);
    procedure TL1Click(Sender: TObject);
    procedure xSum1Click(Sender: TObject);
    procedure Length1Click(Sender: TObject);
    procedure Offset1Click(Sender: TObject);
    procedure Os1Click(Sender: TObject);
    procedure ID1Click(Sender: TObject);
    procedure Ver1Click(Sender: TObject);
    procedure Buffer1Click(Sender: TObject);
    procedure myLocation1Click(Sender: TObject);
    procedure Whois1Click(Sender: TObject);
    procedure Country1Click(Sender: TObject);
    procedure City1Click(Sender: TObject);
    procedure Scanhosts1Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure Idle1Click(Sender: TObject);
    procedure Lowest1Click(Sender: TObject);
    procedure Lower1Click(Sender: TObject);
    procedure Normal1Click(Sender: TObject);
    procedure Higher1Click(Sender: TObject);
    procedure Highest1Click(Sender: TObject);
    procedure imeCritical1Click(Sender: TObject);
    procedure FindDialog1Find(Sender: TObject);
    procedure Button7Click(Sender: TObject);
    procedure coordinates1Click(Sender: TObject);
    procedure OwnerCompany1Click(Sender: TObject);
    procedure PostalNumber1Click(Sender: TObject);
    procedure Region1Click(Sender: TObject);
    procedure ListView1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure Button8Click(Sender: TObject);
  private
    { Private declarations }

    procedure CaptureConsoleOutput(const ACommand, AParameters: String; AMemo: TMemo);
    procedure SetPriorityLevel(P: Byte);

    procedure Gateway;
  public
    { Public declarations }
    abort : boolean;
    procedure WriteOptions;
    procedure ReadOptions;
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

const
  MAX_ADAPTER_DESCRIPTION_LENGTH = 128; // arb.
  MAX_ADAPTER_NAME_LENGTH = 256; // arb.
  MAX_ADAPTER_ADDRESS_LENGTH = 8; // arb.

type
  PIP_ADDRESS_STRING = ^IP_ADDRESS_STRING;
  IP_ADDRESS_STRING = packed record
    acString: array [1..16] of AnsiChar;
  end;

  PIP_MASK_STRING = ^IP_MASK_STRING;
  IP_MASK_STRING = IP_ADDRESS_STRING;

  PIP_ADDR_STRING = ^IP_ADDR_STRING;
  IP_ADDR_STRING = packed record
    Next : PIP_ADDR_STRING;
    IpAddress: IP_ADDRESS_STRING;
    IpMask : IP_MASK_STRING;
    Context : DWORD;
  end;

  time_t = int64;

  PIP_ADAPTER_INFO = ^IP_ADAPTER_INFO;
  IP_ADAPTER_INFO = packed record
    Next : PIP_ADAPTER_INFO;
    ComboIndex : DWORD;
    AdapterName : array [1..MAX_ADAPTER_NAME_LENGTH + 4] of AnsiChar ;
    Description : array [1..MAX_ADAPTER_DESCRIPTION_LENGTH + 4] of AnsiChar;
    AddressLength : UINT;
    Address : array [1..MAX_ADAPTER_ADDRESS_LENGTH] of Byte;
    Index : DWORD;
    dwType : UINT;
    DhcpEnabled : UINT;
    CurrentIpAddress : PIP_ADDR_STRING;
    IpAddressList : IP_ADDR_STRING;
    GatewayList : IP_ADDR_STRING;
    DhcpServer : IP_ADDR_STRING;
    HaveWins : Boolean;
    PrimaryWinsServer : IP_ADDR_STRING;
    SecondaryWinsServer : IP_ADDR_STRING;
    LeaseObtained : time_t;
    LeaseExpires : time_t;
  end;

var
  Form1: TForm1;
  Buffer: array [0..MAX_PACKET_SIZE] of Char;
  flag: Integer;
  hThread: Cardinal;
  stop : Boolean;
  TIF : TIniFile;
  mHandle: THandle;
  ip : Ansistring;

function GetAdaptersInfo(const pAdapterInfo: PIP_ADAPTER_INFO;
    const pOutBufLen: PULONG): DWORD; stdcall;
    external 'IPHLPAPI.DLL' name 'GetAdaptersInfo';

implementation

{$R *.DFM}
// get main path
function MainDir : string;
begin
  Result := ExtractFilePath(ParamStr(0));
end;

procedure TForm1.WriteOptions;    // ################### Options Write
var
  OPT :string;
begin
   OPT := 'Options';

   // Create the options folder if it does not exist.
   if not DirectoryExists(MainDir + 'Data\Options\')
   then ForceDirectories(MainDir + 'Data\Options\');

   // Create the options.ini file.
   TIF := TIniFile.Create(MainDir + 'Data\Options\Options.ini');
   with TIF do
   begin
    WriteBool(OPT,'ip',CheckBox1.Checked);
    WriteBool(OPT,'tcp',CheckBox2.Checked);
    WriteBool(OPT,'udp',CheckBox3.Checked);
    WriteBool(OPT,'icmp',CheckBox4.Checked);
    WriteBool(OPT,'igmp',CheckBox5.Checked);
    WriteBool(OPT,'pup',CheckBox6.Checked);
    WriteBool(OPT,'idp',CheckBox7.Checked);
    WriteBool(OPT,'ggp',CheckBox8.Checked);
    WriteBool(OPT,'ndp',CheckBox9.Checked);
    WriteBool(OPT,'raw',CheckBox10.Checked);
    WriteBool(OPT,'protocol',CheckBox11.Checked);
    WriteBool(OPT,'port',CheckBox12.Checked);
    WriteBool(OPT,'bytes',CheckBox13.Checked);
    WriteBool(OPT,'ttl',CheckBox14.Checked);
    WriteBool(OPT,'length',CheckBox15.Checked);
    WriteInteger(OPT,'PingCount',SpinEdit1.Value);
    WriteInteger(OPT,'Buffer',ComboBox1.ItemIndex);
    WriteBool(OPT,'Panel',Panel.Checked);
    WriteBool(OPT,'ListProtocol',Protocol1.Checked);
    WriteBool(OPT,'ListPort',Port1.Checked);
    WriteBool(OPT,'ListTTL',TL1.Checked);
    WriteBool(OPT,'ListxSum',xSum1.Checked);
    WriteBool(OPT,'ListLength',Length1.Checked);
    WriteBool(OPT,'ListOffset',Offset1.Checked);
    WriteBool(OPT,'ListOs',Os1.Checked);
    WriteBool(OPT,'ListID',ID1.Checked);
    WriteBool(OPT,'ListVer',Ver1.Checked);
    WriteBool(OPT,'ListBuffer',Buffer1.Checked);
    WriteBool(OPT,'Idle',Idle1.Checked);
    WriteBool(OPT,'Lowest',Lowest1.Checked);
    WriteBool(OPT,'Lower',Lower1.Checked);
    WriteBool(OPT,'Normal',Normal1.Checked);
    WriteBool(OPT,'Higher',Higher1.Checked);
    WriteBool(OPT,'Highest',Highest1.Checked);
    WriteBool(OPT,'imeCritical',imeCritical1.Checked);

    WriteBool(OPT,'Cache',CheckBox16.Checked);
    WriteBool(OPT,'ClearBuffer',CheckBox17.Checked);
    WriteBool(OPT,'ClearList',CheckBox18.Checked);
   Free;
   end;
end;

procedure TForm1.ReadOptions;    // ################### Options Read
var OPT:string;
begin
  OPT := 'Options';
  if FileExists(MainDir + 'Data\Options\Options.ini') then
  begin
  TIF:=TIniFile.Create(MainDir + 'Data\Options\Options.ini');
  with TIF do
  begin
    CheckBox1.Checked:=ReadBool(OPT,'ip',CheckBox1.Checked);
    CheckBox2.Checked:=ReadBool(OPT,'tcp',CheckBox2.Checked);
    CheckBox3.Checked:=ReadBool(OPT,'udp',CheckBox3.Checked);
    CheckBox4.Checked:=ReadBool(OPT,'icmp',CheckBox4.Checked);
    CheckBox5.Checked:=ReadBool(OPT,'igmp',CheckBox5.Checked);
    CheckBox6.Checked:=ReadBool(OPT,'pup',CheckBox6.Checked);
    CheckBox7.Checked:=ReadBool(OPT,'idp',CheckBox7.Checked);
    CheckBox8.Checked:=ReadBool(OPT,'ggp',CheckBox8.Checked);
    CheckBox9.Checked:=ReadBool(OPT,'ndp',CheckBox9.Checked);
    CheckBox10.Checked:=ReadBool(OPT,'raw',CheckBox10.Checked);
    CheckBox11.Checked:=ReadBool(OPT,'protocol',CheckBox11.Checked);
    CheckBox12.Checked:=ReadBool(OPT,'port',CheckBox12.Checked);
    CheckBox13.Checked:=ReadBool(OPT,'bytes',CheckBox13.Checked);
    CheckBox14.Checked:=ReadBool(OPT,'ttl',CheckBox14.Checked);
    CheckBox15.Checked:=ReadBool(OPT,'length',CheckBox15.Checked);
    SpinEdit1.Value:=ReadInteger(OPT,'PingCount',SpinEdit1.Value);
    Combobox1.ItemIndex:=ReadInteger(OPT,'Buffer',ComboBox1.ItemIndex);
    Panel.Checked:=ReadBool(OPT,'Panel',Panel.Checked);
    Protocol1.Checked:=ReadBool(OPT,'ListProtocol',Protocol1.Checked);
    Port1.Checked:=ReadBool(OPT,'ListPort',Port1.Checked);
    TL1.Checked:=ReadBool(OPT,'ListTTL',TL1.Checked);
    xSum1.Checked:=ReadBool(OPT,'ListxSum',xSum1.Checked);
    Length1.Checked:=ReadBool(OPT,'ListLength',Length1.Checked);
    Offset1.Checked:=ReadBool(OPT,'ListOffset',Offset1.Checked);
    Os1.Checked:=ReadBool(OPT,'ListOs',Os1.Checked);
    ID1.Checked:=ReadBool(OPT,'ListID',ID1.Checked);
    Ver1.Checked:=ReadBool(OPT,'ListVer',Ver1.Checked);
    Buffer1.Checked:=ReadBool(OPT,'ListBuffer',Buffer1.Checked);
    Idle1.Checked:=ReadBool(OPT,'Idle',Idle1.Checked);
    Lowest1.Checked:=ReadBool(OPT,'Lowest',Lowest1.Checked);
    Lower1.Checked:=ReadBool(OPT,'Lower',Lower1.Checked);
    Normal1.Checked:=ReadBool(OPT,'Normal',Normal1.Checked);
    Higher1.Checked:=ReadBool(OPT,'Higher',Higher1.Checked);
    Highest1.Checked:=ReadBool(OPT,'Highest',Highest1.Checked);
    imeCritical1.Checked:=ReadBool(OPT,'imeCritical',imeCritical1.Checked);

    CheckBox16.Checked:=ReadBool(OPT,'Cache',CheckBox16.Checked);
    CheckBox17.Checked:=ReadBool(OPT,'ClearBuffer',CheckBox17.Checked);
    CheckBox18.Checked:=ReadBool(OPT,'ClearList',CheckBox18.Checked);
  Free;
  end;
  end;
end;

// Determine the gateway
procedure TForm1.Gateway;
var
  dwResult    : DWORD;
  dwLen       : DWORD;
  pAdapterWork : PIP_ADAPTER_INFO;
  pAdapterList : PIP_ADAPTER_INFO;
  iasWork     : IP_ADDR_STRING;

begin
   pAdapterList := nil;
  dwLen       := 0;
  dwResult    := GetAdaptersInfo(pAdapterList,@dwLen);
  if dwResult = ERROR_BUFFER_OVERFLOW then
  begin
    pAdapterList := AllocMem(dwLen);
    try
      dwResult := GetAdaptersInfo(pAdapterList,@dwLen);
      if dwResult = ERROR_SUCCESS then
      begin
        pAdapterWork := pAdapterList;
        repeat
        //ShowMessage(trim(pAdapterWork.AdapterName)); //  interne Name
          iasWork := pAdapterWork.GatewayList;
          while iasWork.Next <> nil do
          begin
            Form1.StatusBar1.Panels[11].Text := (trim(iasWork.IpAddress.acString));
            iasWork := iasWork.Next^;
          end;
          Form1.StatusBar1.Panels[11].Text := (trim(iasWork.IpAddress.acString));
          pAdapterWork := pAdapterWork.Next;
        until pAdapterWork = nil;
      end;
    finally
      FreeMem(pAdapterList,dwLen);
    end;
  end;
end;

// Locate the region of the IP address.
procedure TForm1.Region1Click(Sender: TObject);
var
  item: TListItem;
  city : TStringList;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search region..';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  city := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipinfo.io/' + ip + '/region', Memo2);
    Sleep(150);
    try
      city.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Search IP : ' + ip);
      Memo2.Lines.Add('Region : ' + city.Strings[5]);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    city.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

// Clear Windows cache
procedure DeleteCache;
var
  lpEntryInfo: PInternetCacheEntryInfo;
  hCacheDir: LongWord;
  dwEntrySize: LongWord;
begin
  dwEntrySize := 0;
  // to query the size of the buffer (dwEntrySize)
  FindFirstUrlCacheEntry(nil, TInternetCacheEntryInfo(nil^), dwEntrySize);
  // allocates dynamic memory for a WinINet cache entry structure when
  // interacting with the Windows Internet cache
  GetMem(lpEntryInfo, dwEntrySize);

  if dwEntrySize > 0 then
    lpEntryInfo^.dwStructSize := dwEntrySize;

    // copy buffer (dwEntrySize)
  hCacheDir := FindFirstUrlCacheEntry(nil, lpEntryInfo^, dwEntrySize);

  if hCacheDir <> 0 then
  begin
    repeat
      // deletes a specific URL or file from the Windows Internet cache using the WinINet API
      DeleteUrlCacheEntry(lpEntryInfo^.lpszSourceUrlName);
      // releases a block of dynamic memory in Delphi that was previously allocated using GetMem
      FreeMem(lpEntryInfo, dwEntrySize);
      dwEntrySize := 0;
      // to query the size of the buffer (dwEntrySize)
      FindNextUrlCacheEntry(hCacheDir, TInternetCacheEntryInfo(nil^), dwEntrySize);
      // allocate a specific number of raw bytes in memory for a pointer
      GetMem(lpEntryInfo, dwEntrySize);

      if dwEntrySize > 0 then lpEntryInfo^.dwStructSize := dwEntrySize;
    until not FindNextUrlCacheEntry(hCacheDir, lpEntryInfo^, dwEntrySize);
  end;
  // releases a block of dynamic memory
  FreeMem(lpEntryInfo, dwEntrySize);
  // close cache access
  FindCloseUrlCache(hCacheDir);
end;

// Determine whether the Windows system is online.
function IsOnline: Boolean;
var
  Flags: DWORD;
begin
  Result := InternetGetConnectedState(@Flags, 0);
end;

// disable all components by start scanning
procedure disable;
begin
  Form1.Button2.Enabled := false;
  Form1.Button1.Enabled := true;
  Form1.Button3.Enabled := false;
  Form1.Button6.Enabled := false;
  Form1.Button7.Enabled := false;
  Form1.C1.Enabled := false;
  Form1.C2.Enabled := false;
  Form1.S3.Enabled := false;
  Form1.S1.Enabled := false;
  Form1.S2.Enabled := true;

  Form1.Gethost1.Enabled := false;
  Form1.Ping1.Enabled := false;
  Form1.Whois1.Enabled := false;
  Form1.Locations1.Enabled := false;
  Form1.Scanhosts1.Enabled := false;
end;

// enable all components by stop scanning
procedure enable;
begin
  Form1.Button2.Enabled := true;
  Form1.Button1.Enabled := false;
  Form1.Button3.Enabled := true;
  Form1.Button6.Enabled := true;
  Form1.Button7.Enabled := true;
  Form1.C1.Enabled := true;
  Form1.C2.Enabled := true;
  Form1.S3.Enabled := true;
  Form1.S1.Enabled := true;
  Form1.S2.Enabled := false;

  Form1.Gethost1.Enabled := true;
  Form1.Ping1.Enabled := true;
  Form1.Whois1.Enabled := true;
  Form1.Locations1.Enabled := true;
  Form1.Scanhosts1.Enabled := true;
end;

{ set the priority level of a thread using the Priority property of
  TThread or by calling the Windows API function SetThreadPriority }
procedure TForm1.SetPriorityLevel(P: Byte);
var
  NewPriority: TThreadPriority;
begin
  // Map a byte value to Delphi's TThreadPriority
  case P of
    0: NewPriority := tpIdle;
    1: NewPriority := tpLower;
    2: NewPriority := tpLowest;
    3: NewPriority := tpNormal;
    5: NewPriority := tpHigher;
    6: NewPriority := tpHighest;
    7: NewPriority := tpTimeCritical;
  else
    NewPriority := tpNormal; // Standard-Fallback
  end;
  // Example A: Changing the priority of the current main thread
  // Uses the Windows API from the 'Winapi.Windows' unit.
  case NewPriority of
    tpIdle: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_IDLE);
    tpLowest: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_LOWEST);
    tpLower: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_BELOW_NORMAL);
    tpNormal: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_NORMAL);
    tpHigher: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_ABOVE_NORMAL);
    tpHighest: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_HIGHEST);
    tpTimeCritical: Winapi.Windows.SetThreadPriority(Winapi.Windows.GetCurrentThread,
                                            THREAD_PRIORITY_TIME_CRITICAL);
  end;
  {
  // Example B: If you want to control a background thread:
  if Assigned(MyBackgroundThread) then
    MyBackgroundThread.Priority := NewPriority;
  }

  // display the priority status if necessary
  //ShowMessage('Prioritätsstufe geändert auf Index: ' + P.ToString);
end;

{ get the local IP address in Delphi by using the native Winsock API
  implementation or via cross-platform Indy components }
function GetLocalIP: string;
var
  WSAData: TWSAData;
  HostName: array[0..255] of Char;
  HostInfo: PHostEnt;
  Addr: PInAddr;
begin
  Result := '';
  // initialize Winsock
  if WSAStartup(MakeWord(2, 2), WSAData) = 0 then
  try
   {  If you compile the code `GetHostName(@HostName, SizeOf(HostName))`
      in modern Delphi versions (Delphi 2009 and later), you will very
      likely encounter error E2010 ("Incompatible types: 'Array' and 'PAnsiChar'")
      or issues with the `@` operator. This is because `GetHostName` is an
      old WinSock function that strictly expects 8-bit
      characters (`AnsiChar` / `PAnsiChar`), whereas modern Delphi versions
      use 16-bit Unicode (`Char` = `WideChar`) by default. }
    if GetHostName(@HostName, SizeOf(HostName)) = 0 then
    begin
      // copy hostname
      HostInfo := GetHostByName(@HostName);
      if HostInfo <> nil then
      begin
        // extract the first IP address pointer from a hostent structure
        Addr := PInAddr(HostInfo^.h_addr_list^);
        if Addr <> nil then
          // to convert a null-terminated string (a PChar or PAnsiChar)
          // into a native Delphi string (string or AnsiString)
          Result := StrPas(Inet_NTOA(Addr^));
      end;
    end;
  finally
    WSACleanup;
  end;
end;

// execute windows console and capture the command and result
procedure TForm1.CaptureConsoleOutput(const ACommand, AParameters: String; AMemo: TMemo);
 const
   CReadBuffer = 2400;
 var
   saSecurity: TSecurityAttributes;
   hRead: THandle;
   hWrite: THandle;
   suiStartup: TStartupInfo;
   piProcess: TProcessInformation;
   pBuffer: array[0..CReadBuffer] of AnsiChar;
   dRead: DWord;
   dRunning: DWord;
 begin
   // For Win32 (32-bit), the size is 12 bytes. For Win64 (64-bit), the size is 24 bytes.
   saSecurity.nLength := SizeOf(TSecurityAttributes);
   saSecurity.bInheritHandle := True;
   saSecurity.lpSecurityDescriptor := nil;

   // Win32) and is used in Delphi to create an anonymous pipe
   if CreatePipe(hRead, hWrite, @saSecurity, 0) then
   begin
     // to completely overwrite the entire suiStartup structure with
     // null bytes, thereby initializing it
     FillChar(suiStartup, SizeOf(TStartupInfo), #0);
     // set StartupInfo.cb := SizeOf(TStartupInfo) before passing the
     // TStartupInfo record to the Windows API function CreateProcess
     suiStartup.cb := SizeOf(TStartupInfo);
     suiStartup.hStdInput := hRead;
     suiStartup.hStdOutput := hWrite;
     suiStartup.hStdError := hWrite;
     // redirect input/output handles and control the main window visibility
     suiStartup.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
     // hide console
     suiStartup.wShowWindow := SW_HIDE;

     // create the command process
     if CreateProcess(nil, PChar(ACommand + ' ' + AParameters), @saSecurity,
       @saSecurity, True, NORMAL_PRIORITY_CLASS, nil, nil, suiStartup, piProcess)
       then
     begin
      try
        repeat
           // waits until the process is finished
           dRunning := WaitForSingleObject(piProcess.hProcess, 100);
           Application.ProcessMessages();
           repeat
             dRead := 0;
             ReadFile(hRead, pBuffer[0], CReadBuffer, dRead, nil);
             pBuffer[dRead] := #0;
             // Passing the same buffer as source and destination parameters
             OemToAnsi(pBuffer, pBuffer);
             // buffer output
             AMemo.Lines.Add(String(pBuffer));
           until (dRead < CReadBuffer);
        until (dRunning <> WAIT_TIMEOUT);
       except
        RaiseLastOSError;
       end;
       // close all process
       CloseHandle(piProcess.hProcess);
       CloseHandle(piProcess.hThread);
     end;
     CloseHandle(hRead);
     CloseHandle(hWrite);
   end;
end;

// ping messages
function GetStatusCodeStr(statusCode:integer) : string;
begin
  case statusCode of
    0     : Result:='Success';
    11001 : Result:='Buffer Too Small';
    11002 : Result:='Destination Net Unreachable';
    11003 : Result:='Destination Host Unreachable';
    11004 : Result:='Destination Protocol Unreachable';
    11005 : Result:='Destination Port Unreachable';
    11006 : Result:='No Resources';
    11007 : Result:='Bad Option';
    11008 : Result:='Hardware Error';
    11009 : Result:='Packet Too Big';
    11010 : Result:='Request Timed Out';
    11011 : Result:='Bad Request';
    11012 : Result:='Bad Route';
    11013 : Result:='TimeToLive Expired Transit';
    11014 : Result:='TimeToLive Expired Reassembly';
    11015 : Result:='Parameter Problem';
    11016 : Result:='Source Quench';
    11017 : Result:='Option Too Big';
    11018 : Result:='Bad Destination';
    11032 : Result:='Negotiating IPSEC';
    11050 : Result:='General Failure'
    else
    result:='Unknow';
  end;
end;

{ ------------------------------------------------- Ping -----}
procedure Ping(const Address:string; Retries, BufferSize:Word);
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject   : OLEVariant;
  oEnum         : IEnumvariant;
  iValue        : LongWord;
  i             : Integer;

  PacketsReceived : Integer;
  Minimum         : Integer;
  Maximum         : Integer;
  Average         : Integer;
begin;
  PacketsReceived:=0;
  Minimum        :=0;
  Maximum        :=0;
  Average        :=0;

  Form1.Memo2.Lines.Add('');
  Form1.Memo2.Lines.Add(Format('Pinging %s with %d bytes of data : ',[Address,BufferSize]));

  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer('localhost', 'root\CIMV2', '', '');
  // if a password is required
  //FWMIService   := FSWbemLocator.ConnectServer('192.168.52.130', 'root\CIMV2', 'user', 'password');

  for i := 0 to Retries-1 do
  begin
    FWbemObjectSet:= FWMIService.ExecQuery(Format('SELECT * FROM Win32_PingStatus where Address=%s AND BufferSize=%d',[QuotedStr(Address),BufferSize]),'WQL',0);
    oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
    if oEnum.Next(1, FWbemObject, iValue) = 0 then
    begin
    if Form1.abort = true then
    begin
      Screen.Cursor := crDefault;
      Exit;
    end;
      if FWbemObject.StatusCode=0 then
      begin
        if Form1.abort = true then
        begin
          Screen.Cursor := crDefault;
          Exit;
        end;

        Application.ProcessMessages;
        if FWbemObject.ResponseTime>0 then
          Form1.Memo2.Lines.Add(Format('Reply from (%s) : (bytes = %s) (Time = %sms) (TTL = %s)',
                                       [FWbemObject.ProtocolAddress,
                                        FWbemObject.ReplySize,
                                        FWbemObject.ResponseTime,
                                        FWbemObject.TimeToLive]))
        else
          Form1.Memo2.Lines.Add(Format('Reply from (%s) : (bytes = %s) (Time = %sms) (TTL = %s)',
                                       [FWbemObject.ProtocolAddress,
                                        FWbemObject.ReplySize,
                                        FWbemObject.TimeToLive]));

        Inc(PacketsReceived);

        if FWbemObject.ResponseTime>Maximum then Maximum:=FWbemObject.ResponseTime;
        if Minimum=0 then Minimum:=Maximum;
        if FWbemObject.ResponseTime<Minimum then Minimum:=FWbemObject.ResponseTime;

        Average:=Average+FWbemObject.ResponseTime;
      end
      else
      if not VarIsNull(FWbemObject.StatusCode) then
        Form1.Memo2.Lines.Add(Format('Reply from %s: %s',[FWbemObject.ProtocolAddress,
                                                          GetStatusCodeStr(FWbemObject.StatusCode)]))
      else
        Form1.Memo2.Lines.Add(Format('Reply from %s: %s',[Address,'Error processing request']));
    end;
    FWbemObject := Unassigned;
    FWbemObjectSet := Unassigned;

    if Form1.abort = true then
    begin
      Screen.Cursor := crDefault;
      Exit;
    end;

    Form1.HeaderControl1.Sections[0].Text := 'Report : Pinging.. ' + IntToStr(Retries);
    Application.ProcessMessages;
  end;

  Form1.Memo2.Lines.Add(Format('Ping statistics for %s :',[Address]));
  Form1.Memo2.Lines.Add(Format('    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss),',[Retries,PacketsReceived,Retries-PacketsReceived,Round((Retries-PacketsReceived)*100/Retries)]));

  if PacketsReceived > 0 then
  begin
    Form1.Memo2.Lines.Add('Approximate round trip times in milli-seconds:');
    Form1.Memo2.Lines.Add(Format('    Minimum = %dms, Maximum = %dms, Average = %dms',[Minimum,Maximum,Round(Average/PacketsReceived)]));
  end;

  Form1.HeaderControl1.Sections[0].Text := 'Report : Ping finish';
  Form1.StatusBar1.Panels[3].Text := 'Ping finish';
  Sleep(150);

  if Form1.Button2.Enabled = false then Form1.StatusBar1.Panels[3].Text := 'Scanning..';

  Screen.Cursor := crDefault;
end;

// determine the host of an IP address
function HostToName(IPAddr: AnsiString): AnsiString;
var
  SockAddrIn: TSockAddrIn;
  HostEnt: PHostEnt;
  WSAData: TWSAData;
begin
  // To initialize the Windows Sockets API (Winsock) for network programming
  WSAStartup($101, WSAData);
  { Convert an IPv4 address from string format (e.g., '192.168.1.1') into
    a 32-bit number (DWord / Cardinal) in network byte order (big-endian). }
  SockAddrIn.sin_addr.s_addr := inet_addr(PAnsiChar(IPAddr));
  HostEnt:= GetHostByAddr(@SockAddrIn.sin_addr.S_addr, 4, AF_INET);
  if HostEnt<>nil then
  begin
    Result:=StrPas(Hostent^.h_name)
  end
  else
  begin
    Result:='';
  end;
end;

// To select a specific line in a TMemo field or to scroll to it
procedure Selectline(memo:TMemo;line:integer);
begin
{$R-}  // Deactivate range check
  Memo.SelStart := Memo.Perform(EM_LINEINDEX, line-1, 0);
  Memo.Perform(EM_SCROLLCARET, 0, 0);
  Memo.sellength:=length(Memo.lines.strings[line-1]);
  Memo.SetFocus;
{$R+}
end;

// Intercepting and outputting IP addresses
procedure ListenThread(LV: TListView); stdcall;
var
  lowbyte, hibyte: USHORT;
  wsadata: TWSAData;
  s: TSocket;
  name: array [0..128] of Char;
  phe: PHostent;
  sa: TSockAddrIn;
  sa1: TInAddr;
  count: Integer;
  a, b, c, d, e, f, g, h, j, k : integer; // dont use "i"
  hdr: PIPHeader;
begin
  {$R-}   // Deactivate range check

  // Resets all counters to zero.
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
  // initialize the Windows Sockets library
  WSAStartup(MAKEWORD(2,2), wsadata);

  { When you create a raw socket using `socket(AF_INET, SOCK_RAW, IPPROTO_IP)`,
    you access the IP layer (Layer 3 of the OSI model) directly. This is
    frequently used for network sniffers (capturing all traffic) or
    specialized diagnostic tools. }
  s := socket(AF_INET, SOCK_RAW, IPPROTO_IP);
  // Determine the hostname.
  gethostname(@name, sizeof(name));
  // The parameter expects a pointer to a null-terminated string (PAnsiChar) or
  // (PChar) for older versions of Delphi
  phe := gethostbyname(@name);
  // clear memory
  ZeroMemory(@sa, sizeof(sa));
  { signals to the operating system, during low-level network programming,
    that sockets are for communication via the IPv4 protocol }
  sa.sin_family := AF_INET;
  // to read the first IP address from a hostent structure (network host information)
  // as a 32-bit integer (Cardinal)
  sa.sin_addr.s_addr := cardinal(pointer(phe^.h_addr_list^)^);
  // To bind a socket to a specific local IP address and port
  bind(s, sa, sizeof(TSockaddr));
  // For extended socket commands
  ioctlsocket(s, SIO_RCVALL, flag);
  repeat
     if Form1.Button1.Enabled = false then Exit;
     // returns the size of the pointer (4 or 8 bytes)
     count := recv(s, Buffer, sizeof(Buffer), 0);
      if (count >= sizeof(TIPHeader)) then
      // Output of the ListView caption for the logs
      with LV.Items.Add do
      begin
        hdr := @Buffer;
        // Enter the system time.
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


        // paint the images to the corresponding protocols.
        if Form1.CheckBox1.Checked = true then
        begin
          if  (hdr.iph_protocol < 1)  then
          begin
            ImageIndex := 0;
            SubItems.Add('IP');
          end;
        end;

        if Form1.CheckBox2.Checked = true then
        begin
          if hdr.iph_protocol = 6 then
          begin
            ImageIndex := 1;
            SubItems.Add('TCP');
          end;
        end;

        if Form1.CheckBox3.Checked = true then
        begin
          if hdr.iph_protocol = 17 then
          begin
            ImageIndex := 2;
            SubItems.Add('UDP');
          end;
        end;

        if Form1.CheckBox4.Checked = true then
        begin
          if hdr.iph_protocol = 1 then
          begin
            ImageIndex := 3;
            SubItems.Add('ICMP');
          end;
        end;

        if Form1.CheckBox5.Checked = true then
        begin
          if hdr.iph_protocol = 2 then
          begin
            ImageIndex := 4;
            SubItems.Add('IGMP');
          end;
        end;

        if Form1.CheckBox6.Checked = true then
        begin
          if hdr.iph_protocol = 12 then
          begin
            ImageIndex := 5;
            SubItems.Add('PUP');
          end;
        end;

        if Form1.CheckBox7.Checked = true then
        begin
          if hdr.iph_protocol = 22 then
          begin
            ImageIndex := 6;
            SubItems.Add('IDP');
          end;
        end;

        if Form1.CheckBox8.Checked = true then
        begin
          if hdr.iph_protocol = 3 then
          begin
            ImageIndex := 7;
            SubItems.Add('GGP');
          end;
        end;

        if Form1.CheckBox9.Checked = true then
        begin
          if hdr.iph_protocol = 77 then
          begin
            ImageIndex := 8;
            SubItems.Add('NDP');
          end;
        end;

        if Form1.CheckBox10.Checked = true then
        begin
          if hdr.iph_protocol = 255 then
          begin
            ImageIndex := 9;
            SubItems.Add('RAW');
          end;
        end;

        try
          // Sender's IP address
          sa1.s_addr := hdr.iph_src;
          // converts an IPv4 address (network byte order / in_addr structure) into a readable, dotted string
          SubItems.Add(inet_ntoa(sa1));
          // Destination IP address
          sa1.s_addr := hdr.iph_dest;
          // convert binary network byte order into a readable string in dotted-decimal format
          SubItems.Add(inet_ntoa(sa1));
          // Bitwise right shift by 8 bits
          lowbyte := hdr.iph_length shr 8;
          // To shift the value of the iph_length field 8 bits to the left
          hibyte := hdr.iph_length shl 8;
          // put it together
          hibyte := hibyte + lowbyte;

          // complete output of the information
          SubItems.Add(IntToStr(hibyte));           // Port
          SubItems.Add(IntToStr(hdr.iph_ttl));      // TimeToLive
          SubItems.Add(IntToStr(hdr.iph_xsum));     // Header checksum field
          SubItems.Add(IntToStr(hdr.iph_length));   // Length of an IP header
          SubItems.Add(IntToStr(hdr.iph_offset));   // Fragment offset in IPv4 header
          SubItems.Add(IntToStr(hdr.iph_tos));      // (Type of Service) within an IP header
          SubItems.Add(IntToStr(hdr.iph_id));       // Identification field (ID) within an IPv4 header structure object
          SubItems.Add(IntToStr(hdr.iph_verlen));   // first data field (1 byte) within an IPv4 header structure
          SubItems.Add(IntToStr(sizeof(Buffer)));   // Buffer data size

          if SubItems.Text = '' then
          begin
            Form1.ListView1.Items.Delete(Form1.ListView1.ItemIndex)
          end;
        except
          on E: Exception do
            ShowMessage(E.Message);
        end;
      Form1.StatusBar1.Panels[1].Text := IntToStr(Form1.ListView1.Items.Count);
      end;
  until false;
  {$R+}
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  ThID: Cardinal;
  Rect: TRect;
begin
    {$WARNINGS OFF}
    {$HINTS OFF}
    {$RANGECHECKS OFF}
    {$WARN SYMBOL_PLATFORM OFF}
    {$MINSTACKSIZE $00004000}
    {$MAXSTACKSIZE $00100000}
    {$IMAGEBASE $00400000}
    {$APPTYPE GUI}

  // All components are located on "Panel1" and should operate without flickering.
 Panel1.DoubleBuffered := true;

 // Increase the memo buffer to over 2 GB.
 Memo2.MaxLength := $7FFFFFF0;

 // create margin to report memo
 SendMessage(Memo2.Handle, EM_GETRECT, 0, LongInt(@Rect));
 Rect.Left := 5;
 Rect.Top := 5;
 SendMessage(Memo2.Handle, EM_SETRECT, 0, LongInt(@Rect));

 // initial sniffer thread
 hThread := CreateThread(nil,0, @ListenThread, ListView1,0, ThID);
  if hThread = 0 then
    ShowMessage(SysErrorMessage(GetLastError));

 // Determine local network IP address
 StatusBar1.Panels[7].Text := GetLocalIP;

 // Determine the gateway
 Gateway;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  // safely terminating the thread
  while not TerminateThread(hThread,0) do
    Sleep(50);

  // I'll destroy everything if not.
  Application.Terminate;
end;

// Length of an IP header
procedure TForm1.Length1Click(Sender: TObject);
begin
  if Length1.Checked then
    Listview1.Column[7].Width := 70
  else
    Listview1.Column[7].Width := 0;
end;

// Ping is only possible if one of the protocols has been determined.
procedure TForm1.ListView1Change(Sender: TObject; Item: TListItem;
  Change: TItemChange);
var
  i : integer;
begin
  // scoll list
  if Button2.Enabled = false then
  ListView1.Scroll(0,Item.Position.y);

  // Avoid access errors on the ListView
  i := ListView1.ItemIndex;
    if i =-1 then
       Begin
        Exit;
       End;

  if (ListView1.Selected.SubItems[0] = 'TCP') or
     (ListView1.Selected.SubItems[0] = 'UDP') or
     (ListView1.Selected.SubItems[0] = 'ICMP') or
     (ListView1.Selected.SubItems[0] = 'IGMP') or
     (ListView1.Selected.SubItems[0] = 'GGP') or
     (ListView1.Selected.SubItems[0] = 'PUP') or
     (ListView1.Selected.SubItems[0] = 'IDP') or
     (ListView1.Selected.SubItems[0] = 'NDP') or
     (ListView1.Selected.SubItems[0] = 'RAW') or
     (ListView1.Selected.SubItems[0] = 'IP') then
  begin
    Ping1.Enabled := true;
  end else begin
    Ping1.Enabled := false;
  end;
end;

procedure TForm1.ListView1Click(Sender: TObject);
var
  itemp: Integer;
  item: TListItem;
  i : integer;
  s : Ansistring;
begin
  // Avoid access errors on the ListView
  i := ListView1.ItemIndex;
    if i =-1 then
       Begin
        Exit;
       End;

  if (ListView1.Selected.SubItems[0] = 'TCP') or
     (ListView1.Selected.SubItems[0] = 'UDP') or
     (ListView1.Selected.SubItems[0] = 'ICMP') or
     (ListView1.Selected.SubItems[0] = 'IGMP') or
     (ListView1.Selected.SubItems[0] = 'GGP') or
     (ListView1.Selected.SubItems[0] = 'PUP') or
     (ListView1.Selected.SubItems[0] = 'IDP') or
     (ListView1.Selected.SubItems[0] = 'NDP') or
     (ListView1.Selected.SubItems[0] = 'RAW') or
     (ListView1.Selected.SubItems[0] = 'IP') then
  begin
    Ping1.Enabled := true;
    Button6.Enabled := true;
  end else begin
    Ping1.Enabled := false;
    Button6.Enabled := false;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    StatusBar1.Panels[5].Text := item.SubItems[2];
  end;

  // Select the corresponding domain in the report.
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
    on E: Exception do
      ShowMessage(E.Message);
  end;
end;

// Determine IP address on right-click
procedure TForm1.ListView1MouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
var
  item: TListItem;
begin
  // Check if it is a right-click.
  if Button = mbRight then
  begin
    // Determine the item at the clicked X/Y coordinate
    item := ListView1.GetItemAt(X, Y);
    if Assigned(item) then
    begin
      // Select and focus on the found item.
      ListView1.Selected := item;
      item.Focused := True;
      ip := item.SubItems[2];
      StatusBar1.Panels[5].Text := item.SubItems[2];
    end;
  end;
end;

// Determine the location of the IP address.
procedure TForm1.Location1Click(Sender: TObject);
var
  location : TStringList;
  item: TListItem;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search geolocation';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  location := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipinfo.io/' + ip, Memo2);
    Sleep(150);
    try
      location.Delimiter := ',';
      location.StrictDelimiter := true;
      location.DelimitedText := (Memo2.Text);
      Memo2.Clear;
      Memo2.Lines.Add(#13#10 + location.Text);
    except
      on E: Exception do
      ShowMessage(E.Message);
    end;
  finally
    location.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

procedure TForm1.Lower1Click(Sender: TObject);
begin
  SetPriorityLevel(2);
end;

procedure TForm1.Lowest1Click(Sender: TObject);
begin
  SetPriorityLevel(1);
end;

// Determine my location
procedure TForm1.myLocation1Click(Sender: TObject);
var
  location : TStringList;
  item: TListItem;
begin
  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search my location';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  location := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipconfig.io/json', Memo2);
    Sleep(150);
    try
      location.Delimiter := ',';
      location.StrictDelimiter := true;
      location.DelimitedText := (Memo2.Text);
      Memo2.Clear;
      Memo2.Lines.Add(#13#10 + location.Text);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    location.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

procedure TForm1.Normal1Click(Sender: TObject);
begin
  SetPriorityLevel(3);
end;

// Fragment offset in IPv4 header
procedure TForm1.Offset1Click(Sender: TObject);
begin
  if Offset1.Checked then
    Listview1.Column[8].Width := 50
  else
    Listview1.Column[8].Width := 0;
end;

// (Type of Service) within an IP header
procedure TForm1.Os1Click(Sender: TObject);
begin
  if Os1.Checked then
    Listview1.Column[9].Width := 50
  else
    Listview1.Column[9].Width := 0;
end;

// Determine owner or company of the IP address.
procedure TForm1.OwnerCompany1Click(Sender: TObject);
var
  item: TListItem;
  city : TStringList;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search owner (Company)';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  city := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipconfig.io/asn-org?ip=' + ip, Memo2);
    Sleep(150);
    try
      city.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Search IP : ' + ip);
      Memo2.Lines.Add('Owner (Company) : ' + city.Strings[5]);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    city.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

procedure TForm1.Panel3Click(Sender: TObject);
begin
  Panel2.Visible := Panel.Checked;
end;

procedure TForm1.Ping1Click(Sender: TObject);
begin
  Button6.Click;
end;

procedure TForm1.Port1Click(Sender: TObject);
begin
  if Port1.Checked then
    Listview1.Column[4].Width := 40
  else
    Listview1.Column[4].Width := 0;
end;

// Determine the postal number from region of the IP address.
procedure TForm1.PostalNumber1Click(Sender: TObject);
var
  item: TListItem;
  city : TStringList;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search postal number';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  city := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipinfo.io/' + ip + '/postal', Memo2);
    Sleep(150);
    try
      city.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Search IP : ' + ip);
      Memo2.Lines.Add('Postal Number : ' + city.Strings[5]);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    city.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

procedure TForm1.Protocol1Click(Sender: TObject);
begin
  if Protocol1.Checked then
    Listview1.Column[1].Width := 60
  else
    Listview1.Column[1].Width := 0;
end;

// searching domains names
procedure TForm1.FindDialog1Find(Sender: TObject);
const
  TWordSeperators: set of Char = ['A'..'Z', 'a'..'z', 'ö', 'Ö', 'Ä', 'ä', 'ü', 'Ü', 'ß',
  '´', '`', '@', '0'..'9'];
var
  Buffer: String;
  CmpText: String;
  Position: Integer;
  Counter: Integer;
  Left, Right: Boolean;
  Hit: Boolean;
begin
  if not (frMatchCase in Finddialog1.Options) then
  begin
    CmpText:=AnsiUpperCase(Finddialog1.FindText);
    Buffer := AnsiUpperCase(Copy(Memo2.Text, Memo2.SelStart+Memo1.SelLength+1,
      Length(Memo2.Text)))
  end
  else
  begin
    CmpText := Finddialog1.FindText;
    Buffer:=Copy(Memo2.Text,Memo2.SelStart+Memo2.SelLength+1,Length(Memo2.Text));
  end;

  Position:=AnsiPos(CmpText, Buffer);

  if Position > 0 then
  begin
    if frWholeWord in FindDialog1.Options then
    begin
      Counter:=0;
      Position:=AnsiPos(CmpText, Buffer);
      Hit:=False;
      while (Position > 0) and not Hit do
      begin
        Left:=(Position = 1) or (not (Buffer[Position-1] in TWordSeperators));
        Right:=(Position+Length(Finddialog1.FindText) >= Length(Buffer)) or
          (not (Buffer[Position+Length(Finddialog1.FindText)] in TWordSeperators));
        Hit:=Left and Right;
        Inc(Counter, Position);
        Delete(Buffer, 1, Position);
        Position:=Pos(CmpText, Buffer);
      end;

      if Hit then
      begin
        Memo2.SelStart:= Memo1.SelStart+Memo2.SelLength+Counter-1;
        Memo2.SelLength:= Length(Finddialog1.FindText);
      end
      else
        FindDialog1.CloseDialog;
    end
    else
    begin
      Memo2.SelStart:= Memo2.SelStart+Memo1.SelLength+Position-1;
      Memo2.SelLength:= Length(Finddialog1.FindText);
    end;
  end
  else
    FindDialog1.CloseDialog;
  Memo2.SetFocus;
end;

procedure TForm1.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  WriteOptions;
  while not TerminateThread(hThread,0) do
    Sleep(50);
end;

procedure TForm1.Buffer1Click(Sender: TObject);
begin
  if Buffer1.Checked then
    Listview1.Column[12].Width := 70
  else
    Listview1.Column[12].Width := 0;
end;

// stop scanner thread
procedure TForm1.Button1Click(Sender: TObject);
var
  Buffer : array of Byte;
begin
  Screen.Cursor := crHourGlass;
  StatusBar1.Panels[3].Text := 'Sniffer stop.';

  try
    // Wait until the thread has definitely finished.
    while not TerminateThread(hThread,0) do
    begin
      StatusBar1.Panels[3].Text := 'Scanning stop.';
      Sleep(1000);
    end;
  except
    on E: Exception do
      ShowMessage(E.Message);
  end;

  // clear memory buffer
  if CheckBox17.Checked = true then
  begin
    SetLength(Buffer, 32768);
    ZeroMemory(@Buffer[0], sizeof(Buffer));
  end;

  enable;
  // clear ip Ansistring variable
  ip := '';

  if ListView1.Items.Count <= 0 then
  begin
    Screen.Cursor := crDefault;
    Exit;   // no item go out
  end;

  ListView1.Items.Delete(ListView1.Items.Count - 1);
  Application.ProcessMessages;
  Screen.Cursor := crDefault;
end;

// start scanner thread
procedure TForm1.Button2Click(Sender: TObject);
var
  ThID: Cardinal;
  Buffer : array of Byte;
begin
  // clear memory buffer
  if CheckBox17.Checked = true then
  begin
    SetLength(Buffer, 32768);
    ZeroMemory(@Buffer[0], sizeof(Buffer));
  end;

  if CheckBox16.Checked = true then DeleteCache;

  disable; // disable all components

  // Clear the list or add to it.
  if CheckBox18.Checked = true then
  begin
    ListView1.Clear;
    Memo2.Clear;
  end;

  StatusBar1.Panels[3].Text := 'Scanning..';

  // initial scanner thread
  hThread := CreateThread(nil,0, @ListenThread, ListView1,0,ThID);
    if hThread = 0 then
      ShowMessage(SysErrorMessage(GetLastError));
end;

// Scan the host domains of the identified IPs.
procedure TForm1.Button3Click(Sender: TObject);
var
  i : integer;
  protocol, port, bytes, ttl, length : string;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  Screen.Cursor := crHourGlass;
  disable;
  stop := false;
  Button4.Enabled := true;
  Memo2.Clear;
  Memo2.Enabled := false;
  StatusBar1.Panels[3].Text := 'Scanning Host Domains, please wait..';
  for i := 0 to ListView1.Items.Count -1 do
  begin
    HeaderControl1.Sections[0].Text := 'Report : Scan host ' + IntToStr(Memo2.Lines.Count);
    protocol := '';
       // transfer information
       if CheckBox11.Checked = true then
       begin
        protocol := ListView1.Items[i].SubItems[0]+ ' | ';
       end;

       if CheckBox12.Checked = true then
       begin
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

       {  To determine the corresponding hostname (DNS name) from an
          IP address (reverse DNS lookup) }
        try
          begin
            if HostToName(ListView1.items[i].SubItems[2]) = '' then
            begin
              Memo2.Lines.Add(ListView1.Items[i].SubItems[2] +
                            ' | => | '  + ' (Unknown) or (Socket Error).');
            end else begin
              Memo2.Lines.Add(protocol + port + bytes + Length +
                            ListView1.Items[i].SubItems[2] +
                            ' | Domain =>     '  +
                            HostToName(ListView1.items[i].SubItems[2]));
            end;
          end;
        except
          on E: Exception do
            ShowMessage(E.Message);
        end;

      Application.ProcessMessages;

      // Termination of the investigation
      if stop = true then
      begin
        StatusBar1.Panels[3].Text := 'Scanning abort!';
        Memo2.Enabled := true;
        Screen.Cursor := crDefault;
        Exit;
      end;
    StatusBar1.SetFocus;
    Screen.Cursor := crDefault;
  end;

 enable;
 Memo2.Enabled := true;
 Button4.Enabled := false;
 StatusBar1.Panels[3].Text := 'Scanning done!';
 HeaderControl1.Sections[0].Text := 'Report : Scan host finish';
end;

// Termination of the host to name investigation
procedure TForm1.Button4Click(Sender: TObject);
begin
  stop := true;
  enable;
end;

// abort ping
procedure TForm1.Button5Click(Sender: TObject);
begin
  abort := true;
  StatusBar1.Panels[3].Text := 'Ping abort';
  if Button2.Enabled = false then StatusBar1.Panels[3].Text := 'Scanning..';
  Application.ProcessMessages;
end;

// ping
procedure TForm1.Button6Click(Sender: TObject);
var
  i: Integer;
  item: TListItem;
begin
  abort := false;

  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    StatusBar1.Panels[3].Text := 'Ping (' + ip + ')';
  end;

  try
    // initializes the Component Object Model (COM) library on the
    // current thread, configuring it to use a Single-Threaded Apartment (STA)
    CoInitialize(nil);
    try
      Ping(ip , SpinEdit1.Value, StrToInt(ComboBox1.Text));
    finally
      CoUninitialize;
    end;
  except
    on E:Exception do
        ShowMessage(E.Message);
  end;
   Application.ProcessMessages;
end;

// execute find dialog
procedure TForm1.Button7Click(Sender: TObject);
begin
  FindDialog1.Execute;
  StatusBar1.SetFocus;
end;

procedure TForm1.Button8Click(Sender: TObject);
begin
  MessageDlg('IP Sniffer v 1.3' + chr(10) +
             'Copyright © hackbard' + chr(10) +
             'github.com | Release 2026',mtInformation, [mbOK], 0);

  StatusBar1.SetFocus;
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

// Determine the city associated with the IP address
procedure TForm1.City1Click(Sender: TObject);
var
  item: TListItem;
  city : TStringList;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search city';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  city := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipconfig.io/city?ip=' + ip, Memo2);
    Sleep(150);
    try
      city.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Search IP : ' + ip);
      Memo2.Lines.Add('City : ' + city.Strings[5]);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    city.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

// Determine the coordinates of the IP address.
procedure TForm1.coordinates1Click(Sender: TObject);
var
  item: TListItem;
  city : TStringList;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search coordinates';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  city := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipconfig.io/coordinates?ip=' + ip, Memo2);
    Sleep(150);
    try
      city.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Search IP : ' + ip);
      Memo2.Lines.Add('Coordinates : ' + city.Strings[5]);
      Memo2.Lines.Add('');
      Memo2.Lines.Add('You can locate the exact position using Google Maps.');
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    city.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
end;

// Determine the country associated with the IP address.
procedure TForm1.Country1Click(Sender: TObject);
var
  item: TListItem;
  country : TStringList;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
    HeaderControl1.Sections[0].Text := 'Report : Search country..';
  end;

  Screen.Cursor := crHourGlass;
  Memo2.Clear;
  country := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipconfig.io/country?ip=' + ip, Memo2);
    Sleep(150);
    try
      country.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Search IP : ' + ip);
      Memo2.Lines.Add('Country : ' + country.Strings[5]);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    country.Free;
  end;
  HeaderControl1.Sections[0].Text := 'Report : finish';
  Screen.Cursor := crDefault;
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
  StatusBar1.Panels[1].Text := '0';
  StatusBar1.Panels[5].Text := '';
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
var
  item: TListItem;
  s : string;
begin
  item := ListView1.Selected;
  if item <> nil then
  begin
   s := item.SubItems[2]; Clipboard.AsText := s;
  end;
end;

// save complete ListView report list
procedure TForm1.S3Click(Sender: TObject);
var
  i : integer;
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

  if SaveDialog1.Execute then
  begin
    Memo1.Lines.SaveToFile(SaveDialog1.FileName + '.txt');
  end;
end;

procedure TForm1.Scanhosts1Click(Sender: TObject);
begin
  Button3.Click;
end;

procedure TForm1.TL1Click(Sender: TObject);
begin
  if TL1.Checked then
    Listview1.Column[5].Width := 40
  else
    Listview1.Column[5].Width := 0;
end;

procedure TForm1.Ver1Click(Sender: TObject);
begin
  if Ver1.Checked then
    Listview1.Column[11].Width := 50
  else
    Listview1.Column[11].Width := 0;
end;

// Retrieve the whois information of the IP address (this may be refused).
procedure TForm1.Whois1Click(Sender: TObject);
var
  location : TStringList;
  item: TListItem;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
    ip := item.SubItems[2];
  end;

  Screen.Cursor := crHourGlass;
  HeaderControl1.Sections[0].Text := 'Report : Whois..';
  Memo2.Clear;
  location := TStringList.Create;
  try
    CaptureConsoleOutput('cmd /c', 'curl ipwho.is/' + ip, Memo2);
    Sleep(150);
    try
      location.Assign(Memo2.Lines);
      Memo2.Clear;
      Memo2.Lines.Add('Whois report:'+ #13#10);
      Memo2.Lines.Add(location.Text);
    except
      on E: Exception do
        ShowMessage(E.Message);
    end;
  finally
    location.Free;
    HeaderControl1.Sections[0].Text := 'Report : Whois finish';
  end;

  Screen.Cursor := crDefault;
end;

// Header checksum field
procedure TForm1.xSum1Click(Sender: TObject);
begin
  if xSum1.Checked then
    Listview1.Column[6].Width := 50
  else
    Listview1.Column[6].Width := 0;
end;

procedure TForm1.FormShow(Sender: TObject);
begin
  ReadOptions;

  // Check which columns should be displayed in the list view.
  Panel.OnClick(sender);
  Protocol1.OnClick(sender);
  Port1.OnClick(sender);
  TL1.OnClick(sender);
  xSum1.OnClick(sender);
  Length1.OnClick(sender);
  Offset1.OnClick(sender);
  Os1.OnClick(sender);
  ID1.OnClick(sender);
  Ver1.OnClick(sender);
  Buffer1.OnClick(sender);

  // Check which priority process setting exists.
  Idle1.OnClick(sender);
  Lowest1.OnClick(sender);
  Lower1.OnClick(sender);
  Normal1.OnClick(sender);
  Higher1.OnClick(sender);
  Highest1.OnClick(sender);
  imeCritical1.OnClick(sender);

  // Check the internet connection.
  if IsOnline = true then
  begin
    StatusBar1.Panels[9].Text := 'Yes';
    StatusBar1.Panels[3].Text := 'ready.';
  end else begin
    MessageDlg('Your system is not online; check your internet connection.',mtWarning, [mbOK], 0);
    StatusBar1.Panels[9].Text := 'No';
    StatusBar1.Panels[3].Text := 'No internet connection';
    disable;
    Button1.Enabled := false;
    S2.Enabled := false;
  end;
end;

// Determine the host of a single IP address
procedure TForm1.Gethost1Click(Sender: TObject);
var
  item: TListItem;
  host : string;
begin
  if ListView1.Items.Count <= 0 then
  begin
    Beep;
    MessageDlg('No IP found.',mtInformation, [mbOK], 0);
    Exit;
  end;

  item := ListView1.Selected;
  if item <> nil then
  begin
   ip := item.SubItems[2];
   Clipboard.AsText := ip;
   host := HostToName(ip);

   Memo2.Lines.Add('Destination Ip : ' + ip);
   if host = '' then
   begin
    Memo2.Lines.Add('Host : Unknown or non-existent' + #13#10);
   end else begin
    Memo2.Lines.Add('Host : ' +  HostToName(ip) + #13#10);
   end;
  end;
  HeaderControl1.Sections[0].Text := 'Report : Host';
end;

procedure TForm1.Higher1Click(Sender: TObject);
begin
  SetPriorityLevel(4);
end;

procedure TForm1.Highest1Click(Sender: TObject);
begin
  SetPriorityLevel(5);
end;

procedure TForm1.ID1Click(Sender: TObject);
begin
  if ID1.Checked then
    Listview1.Column[10].Width := 50
  else
    Listview1.Column[10].Width := 0;
end;

procedure TForm1.Idle1Click(Sender: TObject);
begin
  SetPriorityLevel(0);
end;

procedure TForm1.imeCritical1Click(Sender: TObject);
begin
  SetPriorityLevel(6);
end;

{ This serves to prevent the process from being executed a second time on Windows.}
initialization
  mHandle := CreateMutex(nil, True, 'xyz');
  if GetLastError = ERROR_ALREADY_EXISTS then
  begin
    ShowMessage('IP Sniffer is already running !');
    halt;
  end;

finalization
  if mHandle <> 0 then CloseHandle(mHandle);

end.
