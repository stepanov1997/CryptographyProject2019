   M S B A M L   `   `   `  ����R  NCryptographyProject2019, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullK*clr-namespace:CryptographyProject2019.ViewCryptographyProject2019.View  5   	   7    1CryptographyProject2019.View.FileEncryptionWindow   5   	   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   <local*clr-namespace:CryptographyProject2019.View     5   	     � Title$  FileEncryptionWindow��5   	   $	��431��6&   $��503.333��63    � 
ResizeMode$ NoResize=�6C    � WindowStartupLocation$ CenterScreen=�5	   	   .��5
      � $��0,0,-1.333,-4.667q�6   ��5   
   �� 5       �� ImageSource$ /Resources/background.jpg��6   .+�5   
   �� $��FILE ENCRYPTION��6   $
��Left=�6*   $��
170,35,0,0q�6E   $	��Top=�6Y   $��30��5      $	��185��6   $��16(�6(   $
��Bold"�66   $��Italic$�6H    J� RenderTransformOrigin$ 0.596,-0.156&�5      
�������65   �� 5   
   -   5        $
��Back��5      $
��Left=�6    $��
55,345,0,0q�6;   $	��Top=�6O   $��75��6g   5      �� 5   
   $��File to encrypt:��6   
�������$
��Left=�6>   $��
37,120,0,0q�6Y   $	��Top=�5      �� 5   
   -   5        $��
FileButton��5      $��Select��6#   $
��Left=�64   $	��Top=�6O   $	��160��6g   $��175,120,0,0q�5      $��27��6?   �� 5   
   $��Symmetric algorithm:��6   
�������$
��Left=�6B   $��
37,165,0,0q�6]   $	��Top=�5      �� 5   
   -   5        $��SymmetricComboBox��5      $
��Left=�6,   $��175,165,0,0q�6G   $	��Top=�6\   $	��160��5      $��27��6    �� SelectedValuePath$	 Tag��6+    �� SelectedValue 5      �� *YourIntProperty+ �� Mode$ TwoWay=�.@�5      �� -   5        $��AesItem��5      $	��AES��6*   
 � Tag$ 0��68   �� 5      -   5        $��Rc4Item��5      $	��RC2��6*   $ 1��68   �� 5      -   5        $��DesItem��5      $
��DES3��6*   $ 2��69   5      �� 5    
   $��Hash algorithm��6   
�������$
��Left=�6<   $	��Top=�6W   $��
38,210,0,0q�5!      �� 5"   
   -   5        $��HashComboBox��5"      $
��Left=�6'   $��175,210,0,0q�6B   $	��Top=�6W   $	��160��5#      $��27��6   $	 Tag��6+    5$      �� *YourIntProperty+$ TwoWay=�.@�5%      �� -   5        $��SHA1Item��5%      $
��SHA1��6+   $ 0��6:   �� 5&      -	   5        $��
SHA256Item��5&      $��SHA256��6-   $ 1��6>   5'      �� 5(   
   -
   5        $��EncryptButton��5(      $��ENCRYPT FILE��6&   $
��Left=�6=   $��200,345,0,0q�6X   $	��Top=�5)      $	��115��6)   65   �� 5*   
   $��Username of receiver��6   
�������$
��Left=�6B   $��
40,260,0,0q�6]   $	��Top=�5+      �� 5,   
   -   5        $��ReceiverComboBox��5,      $
��Left=�6+   $��175,258,0,0q�6F   $	��Top=�6[   $	��160��5-      $��27��6   5.      5/      