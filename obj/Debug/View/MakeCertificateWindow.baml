   M S B A M L   `   `   `  ����R  NCryptographyProject2019, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullA%clr-namespace:CryptographyProject2019CryptographyProject2019  5   	   8    2CryptographyProject2019.View.MakeCertificateWindow   5   	   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   7local%clr-namespace:CryptographyProject2019     5   	     � Title$  
MainWindow��5   	   $	��431��6   $��503.333��6)    � WindowStartupLocation$ CenterScreen=�69    � 
ResizeMode$ NoResize=�6^   .��5	      � $��0,0,-1.333,-4.667q�6   ��5
   
   �� 5       �� ImageSource$ /Resources/background.jpg��6   .+�5   
   �� $��CREATE USER CERTIFICATE��6   $
��Left=�62   $��
150,40,0,0q�6M   $	��Top=�6a   $��30��5      $	��225��6   $��16(�6(   $
��Bold"�66   $��Italic$�6H    J� RenderTransformOrigin$ 0.596,-0.156&�5      
�������65   �� 5   
   $��Username��6   $
��Left=�6#   $��
30,145,0,0q�6>   $	��Top=�6R   $��30��6j   $	��110��5      
�������6   �� 5   
   -   5        $��UsernameTextBox3��5       �� TextWrapping$ NoWrap=�6*   $
��Left=�6@   $��23��6[   $��155,150,0,0q�5      $	��Top=�6'   $	��140��6?    � ToolTip$ Type username��6K   �� 5   
   -   5        $��CREATE CERTIFICATE��5   +   $
��Left=�6H   $��200,320,0,0q�6c   $	��Top=�5      $	��125��6)   $��25��65   �� 5   
   -   5        $
��Back��5      $
��Left=�6    $��
40,320,0,0q�6;   $	��Top=�6O   $��75��6g   5      �� 5   
   -   5        $��GeneratedCertPath��5      $
��Left=�6+   $��23��6F   $��120,237,0,0q�6R   $
 Wrap=�5      $	��Top=�6&   $	��215��6>    �� 
IsReadOnly . 6J   �� 5   
   $
��Left=�6   $��
20,230,0,0q�6/   $
��Wrap=�6C   $��Path to certificate��6W   $	��Top=�5      $��35��6,   $��85��68   
������� �� TextAlignment$ Center=�6V   5      5      