   M S B A M L   `   `   `  ����U  QPasswordManagerApplication, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullG(clr-namespace:PasswordManagerApplicationPasswordManagerApplication  5   	   +    %PasswordManagerApplication.MainWindow   5   	   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   :local(clr-namespace:PasswordManagerApplication     5   	     � Title$  
MainWindow��5   	   $	��600��6   $	��800��6)   .��5      � .+�5   
   �� -   5         ��Name$ MainTabControl��5      
���   �.@�5      �� $��Login��6   $	��200��6%   .��5      �� .+�5      �� 
�������$��20(�6/   $��5q�5      $��Center=�6'   $��Center=�5      .��69   $"Enter your credentials or register6]   �� 5      
�������$��15(�6/   $	��328��6=   .��6I   
Username6S   �� 5      -   5        $��UsernameBox��5      $	��328��61   $��25��6=   $��15(�6I   �� 5      
�������$��15(�6/   $	��328��6=   .��6I   
Password6S   G� 5      -   5        $��PasswordBox��5   "   $	��328��65   $��25��6A   $��15(�6M   �� 5      -   5        $��Login��5      
���   �
�������$��15(�5      $��10q�6+   $	��328��67   
��� � �$��2q�5   0   �� 5      -   5        $��Register��5      
���   �
�������$��15(�5      $��10q�6+   $	��328��67   
����d�$��2q�5    :   5!      5"      �� 5#      -   5         ��Name$ ManagePasswordsTab��5#   0   $��Manage Passwords��6   ${�False��5$      $	��200��6(   .��5%      �� .+�5&      �� -   5        $��SearchTitleBox��5&      �� 5'      -   5        $��Search��5'      6.   &   System.Windows.Controls.DataGrid  5)      -	   5        $��PasswordGrid��5)         AutoGenerateColumns$ False��63      Columns 5*      0  *System.Windows.Controls.DataGridTextColumn  5+      ,  &System.Windows.Controls.DataGridColumn   Header$ Title��61      Width5  /System.Windows.Controls.DataGridLengthConverter$ * 6Z   1  +System.Windows.Controls.DataGridBoundColumn   Binding 6@   �� *Title+6Z     5,      $ Encrypted Password��61   $ * 6s    6M   �� *EncryptedPassword+6s     5-      $ URL/Application��61   $ * 6b    6J   �� *Url+6b     5.      $ Comment��61   $ * 6^    6B   �� *	Comment+6^   4  .System.Windows.Controls.DataGridTemplateColumn  5/      $ Decrypted Password��65   $ * 6Q      CellTemplate 50   "   �� 51   &   .R�52   *   �� 	 �� Orientation$	 
Horizontal=�65   .+�53   .   �� $	��200��6f   
 �� 
IsReadOnly$

 True��6r   ��66   �� *DecryptedPassword+ �� Mode$ OneWay=�6r   �� 54   .   -
   5        $
��Show��54   5   
 � Tag 6e   �� *EncryptedPassword+ � DataContext 6�   �� �� 55   .   -   5        $
��Copy��55   5    6e   �� 56   +   57   '   59      5;      �� 5=      -   5        $��NewPasswordBox��5=      $%��enter your new password here...��64   �� 5>      -   5        $��Load All Passwords��5>      6:   �� 5?      -   5        $��Add New Password��5?      68   �� 5@      -   5        $��Update Password��5@      67   �� 5A      -   5        $��Delete Password��5A      67   �� 5B      -   5        $��Generate Random Password��5B      6@   5C      5D      5E      5F      5G      