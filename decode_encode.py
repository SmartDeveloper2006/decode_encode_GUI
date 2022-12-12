from tkinter import*


root=Tk()
root.geometry("900x500")
root.title('Yashirin Xabarlar')
title=Label(root,text='Shifrlangan xabarlar',font=('helvetica', 30, 'bold'))
title.place(x=260,y=5)

rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()

name= Label(root, font=('arial', 16, 'bold'), text="Ismingiz:", bd=16, )
name.place(x=80,y=75)
name_txt = Entry(root, font=('arial', 16, 'bold'),width=47,textvariable=rand, bd=10, insertwidth=5,bg="powder blue")
name_txt.place(x=200,y=80)

xabar= Label(root, font=('arial', 16, 'bold'), text="Xabar:", bd=16, )
xabar.place(x=80,y=135)
xabar_txt = Entry(root, font=('arial', 16, 'bold'),width=47,textvariable=Msg, bd=10, insertwidth=5,bg="powder blue")
xabar_txt.place(x=200,y=140)

kalit= Label(root, font=('arial', 16, 'bold'), text="Parol:", bd=16, )
kalit.place(x=80,y=205)
kalit_txt = Entry(root, font=('arial', 16, 'bold'),width=47,textvariable=key, bd=10, insertwidth=5,bg="powder blue")
kalit_txt.place(x=200,y=210)

lblmode = Label(root, font=('arial', 16, 'bold'),
                text="e -> Encode, d -> Decode",
                bd=16, anchor="w")

lblmode.place(x=50, y=275)

txtmode = Entry(root,width=35, font=('arial', 16, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg="powder blue")

txtmode.place(x=350, y=275)

txtService = Entry(root, width=57,font=('arial', 16, 'bold'), textvariable=Result, bd=10, insertwidth=4,bg="powder blue", justify='right')
txtService.place(x=100, y=435)
#### deflar ####

def qExit():
    root.destroy()

def Reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")

import base64
def encode(key, clear):
    enc = []

    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) +
                     ord(key_c)) % 256)

        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Function to decode
def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)

        dec.append(dec_c)
    return "".join(dec)

def Ref():


    clear = Msg.get()
    k = key.get()
    m = mode.get()

    if (m == 'e'):
        Result.set(encode(k, clear))
    else:
        Result.set(decode(k, clear))

##### buttonlar ######
# Show message button
btnTotal = Button(root, padx=16, pady=8, bd=16, fg="black",font=('arial', 16, 'bold'), width=10,text="O'zgartirish", bg="yellow",command=Ref).place(x=100, y=335)
#
# Reset button
btnReset = Button(root, padx=16, pady=8, bd=16,fg="black", font=('arial', 16, 'bold'), width=10, text="Tozalash", bg="blue",command=Reset).place(x=350, y=335)
#
# Exit button
btnExit = Button(root, padx=16, pady=8, bd=16,fg="black", font=('arial', 16, 'bold'), width=10, text="Chiqish", bg="yellow",command=qExit).place(x=600, y=335)
root.mainloop()