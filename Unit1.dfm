object Form1: TForm1
  Left = 1557
  Top = 170
  Caption = 'IP Sniffer'
  ClientHeight = 468
  ClientWidth = 841
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  Position = poScreenCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnShow = FormShow
  TextHeight = 13
  object StatusBar1: TStatusBar
    Left = 0
    Top = 449
    Width = 841
    Height = 19
    Panels = <
      item
        Text = 'Ip :'
        Width = 30
      end
      item
        Width = 100
      end
      item
        Text = 'Status :'
        Width = 50
      end
      item
        Width = 300
      end
      item
        Text = 'Selected :'
        Width = 50
      end
      item
        Width = 90
      end>
    ExplicitTop = 454
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 198
    Height = 449
    Align = alLeft
    TabOrder = 1
    object Bevel1: TBevel
      Left = 8
      Top = 225
      Width = 145
      Height = 2
    end
    object Label1: TLabel
      Left = 15
      Top = 9
      Width = 79
      Height = 26
      Caption = 'IP Sniffer'
      Font.Charset = ANSI_CHARSET
      Font.Color = clWindowText
      Font.Height = -21
      Font.Name = 'Impact'
      Font.Style = []
      ParentFont = False
    end
    object Label2: TLabel
      Left = 16
      Top = 240
      Width = 69
      Height = 13
      Caption = 'Host Domains:'
    end
    object Bevel2: TBevel
      Left = 8
      Top = 41
      Width = 147
      Height = 2
    end
    object Bevel3: TBevel
      Left = 8
      Top = 403
      Width = 147
      Height = 2
    end
    object Button1: TButton
      Left = 104
      Top = 58
      Width = 77
      Height = 20
      Caption = 'stop'
      TabOrder = 0
      TabStop = False
      OnClick = Button1Click
    end
    object Button2: TButton
      Left = 8
      Top = 58
      Width = 77
      Height = 20
      Caption = 'start'
      Enabled = False
      TabOrder = 1
      OnClick = Button2Click
    end
    object CheckBox1: TCheckBox
      Left = 24
      Top = 88
      Width = 66
      Height = 17
      Caption = 'IP (0)'
      Checked = True
      State = cbChecked
      TabOrder = 2
      OnClick = CheckBox1Click
    end
    object CheckBox2: TCheckBox
      Left = 24
      Top = 113
      Width = 66
      Height = 17
      Caption = 'TCP (0)'
      Checked = True
      State = cbChecked
      TabOrder = 3
      OnClick = CheckBox2Click
    end
    object CheckBox3: TCheckBox
      Left = 24
      Top = 136
      Width = 79
      Height = 17
      Caption = 'UDP (0)'
      Checked = True
      State = cbChecked
      TabOrder = 4
      OnClick = CheckBox3Click
    end
    object CheckBox4: TCheckBox
      Left = 24
      Top = 160
      Width = 79
      Height = 17
      Caption = 'ICMP (0)'
      Checked = True
      State = cbChecked
      TabOrder = 5
      OnClick = CheckBox4Click
    end
    object CheckBox5: TCheckBox
      Left = 24
      Top = 184
      Width = 79
      Height = 17
      Caption = 'IGMP (0)'
      TabOrder = 6
      OnClick = CheckBox5Click
    end
    object CheckBox6: TCheckBox
      Left = 112
      Top = 88
      Width = 73
      Height = 17
      Caption = 'PUP (0)'
      TabOrder = 7
      OnClick = CheckBox6Click
    end
    object CheckBox7: TCheckBox
      Left = 112
      Top = 111
      Width = 73
      Height = 17
      Caption = 'IDP (0)'
      TabOrder = 8
      OnClick = CheckBox7Click
    end
    object CheckBox8: TCheckBox
      Left = 112
      Top = 134
      Width = 73
      Height = 17
      Caption = 'GGP (0)'
      Checked = True
      State = cbChecked
      TabOrder = 9
      OnClick = CheckBox8Click
    end
    object CheckBox9: TCheckBox
      Left = 112
      Top = 160
      Width = 73
      Height = 17
      Caption = 'NDP (0)'
      TabOrder = 10
      OnClick = CheckBox9Click
    end
    object CheckBox10: TCheckBox
      Left = 112
      Top = 184
      Width = 73
      Height = 17
      Caption = 'RAW (0)'
      TabOrder = 11
      OnClick = CheckBox10Click
    end
    object Button3: TButton
      Left = 16
      Top = 355
      Width = 69
      Height = 25
      Caption = 'Scan Hosts'
      TabOrder = 12
      OnClick = Button3Click
    end
    object CheckBox11: TCheckBox
      Left = 24
      Top = 272
      Width = 61
      Height = 17
      TabStop = False
      Caption = 'Protocol'
      Checked = True
      State = cbChecked
      TabOrder = 13
    end
    object CheckBox12: TCheckBox
      Left = 24
      Top = 295
      Width = 44
      Height = 17
      TabStop = False
      Caption = 'Port'
      Checked = True
      State = cbChecked
      TabOrder = 14
    end
    object CheckBox13: TCheckBox
      Left = 24
      Top = 318
      Width = 50
      Height = 17
      TabStop = False
      Caption = 'Bytes'
      Checked = True
      State = cbChecked
      TabOrder = 15
    end
    object CheckBox14: TCheckBox
      Left = 112
      Top = 272
      Width = 44
      Height = 17
      TabStop = False
      Caption = 'TTL'
      Checked = True
      State = cbChecked
      TabOrder = 16
    end
    object CheckBox15: TCheckBox
      Left = 112
      Top = 295
      Width = 61
      Height = 17
      TabStop = False
      Caption = 'Length'
      Checked = True
      State = cbChecked
      TabOrder = 17
    end
    object Button4: TButton
      Left = 104
      Top = 355
      Width = 77
      Height = 25
      Caption = 'stop'
      Enabled = False
      TabOrder = 18
      OnClick = Button4Click
    end
  end
  object Panel2: TPanel
    Left = 198
    Top = 0
    Width = 643
    Height = 449
    Align = alClient
    TabOrder = 2
    object Splitter1: TSplitter
      Left = 1
      Top = 298
      Width = 641
      Height = 5
      Cursor = crVSplit
      Align = alBottom
      ExplicitTop = 413
      ExplicitWidth = 746
    end
    object Memo2: TMemo
      Left = 1
      Top = 303
      Width = 641
      Height = 145
      TabStop = False
      Align = alBottom
      Font.Charset = ANSI_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Courier New'
      Font.Style = [fsBold]
      HideSelection = False
      ParentFont = False
      ScrollBars = ssBoth
      TabOrder = 0
    end
    object ListView1: TListView
      Left = 1
      Top = 1
      Width = 641
      Height = 297
      Align = alClient
      BorderStyle = bsNone
      Columns = <
        item
          Caption = 'Time :'
          Width = 70
        end
        item
          Caption = 'Protocol :'
          Width = 60
        end
        item
          Caption = 'Local :'
          Width = 100
        end
        item
          Caption = 'Destination :'
          Width = 100
        end
        item
          Caption = 'Port :'
          Width = 40
        end
        item
          Caption = 'TTL :'
          Width = 40
        end
        item
          Caption = 'XSum :'
        end
        item
          Caption = 'Length :'
          Width = 70
        end
        item
          Caption = 'Offset :'
        end
        item
          Caption = 'TOs :'
        end
        item
          Caption = 'ID :'
        end
        item
          Caption = 'Ver :'
        end
        item
          Caption = 'Buffer :'
          Width = 70
        end>
      ColumnClick = False
      GridLines = True
      RowSelect = True
      PopupMenu = PopupMenu1
      TabOrder = 1
      ViewStyle = vsReport
      OnChange = ListView1Change
      OnClick = ListView1Click
      ExplicitLeft = 6
      ExplicitTop = 0
    end
    object Memo1: TMemo
      Left = 49
      Top = 182
      Width = 89
      Height = 49
      ReadOnly = True
      ScrollBars = ssBoth
      TabOrder = 2
      Visible = False
    end
  end
  object PopupMenu1: TPopupMenu
    Left = 296
    Top = 64
    object S1: TMenuItem
      Caption = 'Start'
      OnClick = S1Click
    end
    object S2: TMenuItem
      Caption = 'Stop'
      OnClick = S2Click
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object C1: TMenuItem
      Caption = 'Clear'
      OnClick = C1Click
    end
    object N2: TMenuItem
      Caption = '-'
    end
    object C2: TMenuItem
      Caption = 'Copy Destination IP'
      OnClick = C2Click
    end
    object S3: TMenuItem
      Caption = 'Save log'
      OnClick = S3Click
    end
  end
  object SaveDialog1: TSaveDialog
    Left = 384
    Top = 64
  end
end
