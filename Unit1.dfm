object Form1: TForm1
  Left = 1557
  Top = 170
  Width = 983
  Height = 383
  Caption = 'IP Sniffer'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object ListView1: TListView
    Left = 97
    Top = 0
    Width = 870
    Height = 325
    Align = alClient
    BorderStyle = bsNone
    Columns = <
      item
        Caption = 'Time :'
        Width = 80
      end
      item
        Caption = 'Protocol :'
        Width = 70
      end
      item
        Caption = 'Local :'
        Width = 120
      end
      item
        Caption = 'Destination :'
        Width = 120
      end
      item
        Caption = 'Port :'
        Width = 70
      end
      item
        Caption = 'TTL'
      end
      item
        Caption = 'XSum :'
      end
      item
        Caption = 'Length:'
      end
      item
        Caption = 'Offset:'
      end
      item
        Caption = 'TOs:'
      end
      item
        Caption = 'ID:'
      end
      item
        Caption = 'Ver:'
      end
      item
        Caption = 'Buffer:'
      end>
    ColumnClick = False
    GridLines = True
    RowSelect = True
    PopupMenu = PopupMenu1
    TabOrder = 0
    ViewStyle = vsReport
    OnChange = ListView1Change
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 325
    Width = 967
    Height = 19
    Panels = <>
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 97
    Height = 325
    Align = alLeft
    TabOrder = 2
    object Button1: TButton
      Left = 8
      Top = 40
      Width = 75
      Height = 20
      Caption = 'stop'
      TabOrder = 0
      OnClick = Button1Click
    end
    object Button2: TButton
      Left = 8
      Top = 16
      Width = 75
      Height = 20
      Caption = 'start'
      Enabled = False
      TabOrder = 1
      OnClick = Button2Click
    end
    object CheckBox1: TCheckBox
      Left = 24
      Top = 72
      Width = 41
      Height = 17
      Caption = 'IP'
      Checked = True
      State = cbChecked
      TabOrder = 2
      OnClick = CheckBox1Click
    end
    object CheckBox2: TCheckBox
      Left = 24
      Top = 96
      Width = 41
      Height = 17
      Caption = 'TCP'
      Checked = True
      State = cbChecked
      TabOrder = 3
      OnClick = CheckBox2Click
    end
    object CheckBox3: TCheckBox
      Left = 24
      Top = 120
      Width = 45
      Height = 17
      Caption = 'UDP'
      Checked = True
      State = cbChecked
      TabOrder = 4
      OnClick = CheckBox3Click
    end
    object CheckBox4: TCheckBox
      Left = 24
      Top = 144
      Width = 49
      Height = 17
      Caption = 'ICMP'
      Checked = True
      State = cbChecked
      TabOrder = 5
      OnClick = CheckBox4Click
    end
    object CheckBox5: TCheckBox
      Left = 24
      Top = 168
      Width = 49
      Height = 17
      Caption = 'IGMP'
      TabOrder = 6
      OnClick = CheckBox5Click
    end
    object CheckBox6: TCheckBox
      Left = 24
      Top = 192
      Width = 41
      Height = 17
      Caption = 'PUP'
      TabOrder = 7
      OnClick = CheckBox6Click
    end
    object CheckBox7: TCheckBox
      Left = 24
      Top = 216
      Width = 41
      Height = 17
      Caption = 'IDP'
      TabOrder = 8
      OnClick = CheckBox7Click
    end
    object CheckBox8: TCheckBox
      Left = 24
      Top = 240
      Width = 41
      Height = 17
      Caption = 'GGP'
      Checked = True
      State = cbChecked
      TabOrder = 9
      OnClick = CheckBox8Click
    end
    object CheckBox9: TCheckBox
      Left = 24
      Top = 264
      Width = 41
      Height = 17
      Caption = 'NDP'
      TabOrder = 10
      OnClick = CheckBox9Click
    end
    object CheckBox10: TCheckBox
      Left = 24
      Top = 288
      Width = 49
      Height = 17
      Caption = 'RAW'
      TabOrder = 11
      OnClick = CheckBox10Click
    end
  end
  object Memo1: TMemo
    Left = 120
    Top = 264
    Width = 89
    Height = 49
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 3
    Visible = False
  end
  object PopupMenu1: TPopupMenu
    Left = 200
    Top = 56
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
    Left = 208
    Top = 96
  end
end
