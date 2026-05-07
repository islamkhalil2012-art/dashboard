import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ------------------------------
# إدخال البيانات المستخرجة من الصور
# ------------------------------
data = {
    "الكلية": [],
    "البرنامج": [],
    "عدد السداد": [],
    "إجمالي الطلاب": [],
    "نسبة السداد (%)": []
}

# كلية التجارة (من الصورة الأولى)
commerce_progs = [
    ("برنامج الساعات المعتمدة الداخلية", 633, 738, 85.77),
    ("تخصص محاسبة الداخلية", 986, 1152, 85.59),
    ("تخصص إدارة الأعمال والتجارة الإلكترونية", 114, 124, 91.94),
    ("تخصص الإحصاء والعلوم البيانات", 24, 25, 96.0),
    ("تخصص الاقتصاد", 124, 134, 92.54),
    ("BIS نظام معلومات الأعمال عربي", 141, 160, 88.13),
    ("الساعات المعتمدة انتساب", 2, 2, 100.0),
    ("ABA المحاسبة وتحليل الأعمال انتساب", 142, 159, 89.31),
    ("BIS داخلي انتساب", 48, 75, 84.21),
    ("الساعات المعتمدة انتساب العبور", 150, 193, 64.0),
    ("ABA داخلي انتساب العبور", 2, 152, 66.67),
    ("BIS داخلي انتساب العبور", 109, 692, 71.71),
    ("تخصص إدارة الأعمال انتساب", 49, 60, 81.67),
    ("تخصص المحاسبة انتساب العبور", 17, 23, 73.91),
    ("تخصص الإحصاء انتساب العبور", 263, 321, 81.93),
    ("تخصص إدارة الأعمال انتساب العبور", 120, 140, 85.71),
]
for name, paid, total, perc in commerce_progs:
    if total > 0:
        data["الكلية"].append("التجارة")
        data["البرنامج"].append(name)
        data["عدد السداد"].append(paid)
        data["إجمالي الطلاب"].append(total)
        data["نسبة السداد (%)"].append(perc)

# كلية الحاسبات والذكاء الاصطناعي
data["الكلية"].append("الحاسبات"); data["البرنامج"].append("معلوماتية طبية"); data["عدد السداد"].append(25); data["إجمالي الطلاب"].append(28); data["نسبة السداد (%)"].append(89.29)
data["الكلية"].append("الحاسبات"); data["البرنامج"].append("أمن المعلومات"); data["عدد السداد"].append(209); data["إجمالي الطلاب"].append(409); data["نسبة السداد (%)"].append(51.10)

# كلية الهندسة
data["الكلية"].append("الهندسة"); data["البرنامج"].append("هندسة الحاسبات المدمجة"); data["عدد السداد"].append(102); data["إجمالي الطلاب"].append(106); data["نسبة السداد (%)"].append(96.23)
data["الكلية"].append("الهندسة"); data["البرنامج"].append("هندسة كهربائية"); data["عدد السداد"].append(230); data["إجمالي الطلاب"].append(245); data["نسبة السداد (%)"].append(93.88)
data["الكلية"].append("الهندسة"); data["البرنامج"].append("هندسة إدارة التشغيل"); data["عدد السداد"].append(117); data["إجمالي الطلاب"].append(127); data["نسبة السداد (%)"].append(92.13)
data["الكلية"].append("الهندسة"); data["البرنامج"].append("هندسة معلومات"); data["عدد السداد"].append(362); data["إجمالي الطلاب"].append(388); data["نسبة السداد (%)"].append(93.30)

# كلية الطب البيطري
vet_progs = [
    ("جودة ومراقبة الغذاء", 230, 237, 97.05),
    ("الأدوية البيطرية", 193, 209, 92.34),
    ("طب وجراحة الحيوانات الأليفة", 299, 315, 94.92),
    ("تكنولوجيا حيوية", 345, 361, 95.57),
    ("طب الطيور والأرانب", 108, 110, 98.18)
]
for name, paid, total, perc in vet_progs:
    data["الكلية"].append("الطب البيطري")
    data["البرنامج"].append(name)
    data["عدد السداد"].append(paid)
    data["إجمالي الطلاب"].append(total)
    data["نسبة السداد (%)"].append(perc)

# كلية الزراعة
data["الكلية"].append("الزراعة"); data["البرنامج"].append("التقديرات الحيوية الزراعية"); data["عدد السداد"].append(175); data["إجمالي الطلاب"].append(209); data["نسبة السداد (%)"].append(83.73)
data["الكلية"].append("الزراعة"); data["البرنامج"].append("سلامة الغذاء"); data["عدد السداد"].append(119); data["إجمالي الطلاب"].append(144); data["نسبة السداد (%)"].append(82.64)
data["الكلية"].append("الزراعة"); data["البرنامج"].append("هندسة النظم الزراعية"); data["عدد السداد"].append(7); data["إجمالي الطلاب"].append(9); data["نسبة السداد (%)"].append(77.78)

# كلية الفنون التطبيقية
data["الكلية"].append("فنون تطبيقية"); data["البرنامج"].append("علوم وتصميم الآلات"); data["عدد السداد"].append(448); data["إجمالي الطلاب"].append(535); data["نسبة السداد (%)"].append(83.74)
data["الكلية"].append("فنون تطبيقية"); data["البرنامج"].append("الميدان"); data["عدد السداد"].append(186); data["إجمالي الطلاب"].append(201); data["نسبة السداد (%)"].append(92.54)

# كلية الآداب
data["الكلية"].append("الآداب"); data["البرنامج"].append("تقنيات الرقمنة"); data["عدد السداد"].append(40); data["إجمالي الطلاب"].append(55); data["نسبة السداد (%)"].append(72.7)
data["الكلية"].append("الآداب"); data["البرنامج"].append("ترجمة إنجليزية"); data["عدد السداد"].append(30); data["إجمالي الطلاب"].append(48); data["نسبة السداد (%)"].append(62.5)

# ------------------------------
# تحويل إلى DataFrame
# ------------------------------
df = pd.DataFrame(data)
df = df[df["إجمالي الطلاب"] > 0]

# ------------------------------
# تطبيق Streamlit
# ------------------------------
st.set_page_config(page_title="داشبورد نسب سداد الطلاب", layout="wide")
st.markdown("<h1 style='text-align: center;'>📊 إحصائية سداد الرسوم الدراسية 2025-2026</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>جامعة بنها - جميع الكليات</h3>", unsafe_allow_html=True)

# مرشحات جانبية
st.sidebar.header("🔍 فلترة البيانات")
college_filter = st.sidebar.multiselect("اختر الكلية", options=df["الكلية"].unique(), default=df["الكلية"].unique())
perc_min, perc_max = st.sidebar.slider("نسبة السداد (%)", 0, 100, (50, 100))
search_prog = st.sidebar.text_input("بحث باسم البرنامج")

filtered_df = df[
    (df["الكلية"].isin(college_filter)) &
    (df["نسبة السداد (%)"] >= perc_min) &
    (df["نسبة السداد (%)"] <= perc_max)
]
if search_prog:
    filtered_df = filtered_df[filtered_df["البرنامج"].str.contains(search_prog, case=False, na=False)]

# مؤشرات KPI
total_students = filtered_df["إجمالي الطلاب"].sum()
total_paid = filtered_df["عدد السداد"].sum()
avg_perc = (total_paid / total_students * 100) if total_students > 0 else 0
num_progs = filtered_df.shape[0]
min_perc = filtered_df["نسبة السداد (%)"].min() if num_progs > 0 else 0
max_perc = filtered_df["نسبة السداد (%)"].max() if num_progs > 0 else 0
lowest_prog = filtered_df.loc[filtered_df["نسبة السداد (%)"].idxmin(), "البرنامج"] if num_progs > 0 else ""

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("🎓 إجمالي الطلاب", f"{total_students:,}")
col2.metric("💰 نسبة السداد الإجمالية", f"{avg_perc:.2f}%")
col3.metric("📚 عدد البرامج", num_progs)
col4.metric("🔻 أقل نسبة", f"{min_perc:.1f}% - {lowest_prog[:20]}")
col5.metric("🔺 أعلى نسبة", f"{max_perc:.1f}%")

st.divider()

col_chart1, col_chart2 = st.columns(2)

# 1. نسب السداد لكل كلية
college_avg = filtered_df.groupby("الكلية")["نسبة السداد (%)"].mean().sort_values().reset_index()
fig1 = px.bar(college_avg, x="نسبة السداد (%)", y="الكلية", orientation='h', title="📈 متوسط نسبة السداد لكل كلية",
              color="نسبة السداد (%)", color_continuous_scale="Viridis", text="نسبة السداد (%)")
fig1.update_traces(texttemplate='%{text:.1f}%', textposition='outside')
col_chart1.plotly_chart(fig1, use_container_width=True)

# 2. أكثر 10 برامج انخفاضًا
lowest_progs = filtered_df.nsmallest(10, "نسبة السداد (%)")[["البرنامج", "الكلية", "نسبة السداد (%)"]]
fig2 = px.bar(lowest_progs, x="نسبة السداد (%)", y="البرنامج", orientation='h', title="⚠️ البرامج الأقل سدادًا (تحتاج متابعة)",
              color="نسبة السداد (%)", color_continuous_scale="reds", text="نسبة السداد (%)")
fig2.update_traces(texttemplate='%{text:.1f}%', textposition='outside')
col_chart2.plotly_chart(fig2, use_container_width=True)

st.divider()
col_chart3, col_chart4 = st.columns(2)

# 3. توزيع الطلاب
students_by_college = filtered_df.groupby("الكلية")["إجمالي الطلاب"].sum().reset_index()
fig3 = px.pie(students_by_college, values="إجمالي الطلاب", names="الكلية", title="📌 توزيع الطلاب بين الكليات", hole=0.3)
col_chart3.plotly_chart(fig3, use_container_width=True)

# 4. جدول تفصيلي
st.subheader("📋 تفاصيل كل برنامج")
st.dataframe(
    filtered_df[["الكلية", "البرنامج", "عدد السداد", "إجمالي الطلاب", "نسبة السداد (%)"]]
    .sort_values("نسبة السداد (%)", ascending=False),
    use_container_width=True,
    height=400
)

st.caption("تم إنشاء الداشبورد بناءً على بيانات مستخرجة من صور النظام - آخر تحديث: مايو 2026")