<template>
  <div class="training">
    <div class="page-header">
      <span class="page-title">安全培训 / {{ pageTitle }}</span>
      <el-button v-if="isSecops && tab === 'courses'" type="primary" @click="openCourse()">
        <el-icon><Plus /></el-icon>&nbsp;新建课程
      </el-button>
      <el-button v-if="isSecops && tab === 'questions'" type="primary" plain @click="qVisible = true">新增题目</el-button>
    </div>

    <!-- 课程列表 -->
    <div v-if="tab === 'courses'">
      <el-row :gutter="16">
        <el-col :span="8" v-for="c in courses" :key="c.id">
          <el-card shadow="hover" class="course-card">
            <div class="course-body">
              <div class="course-cat">{{ c.category }}</div>
              <div class="course-title">{{ c.title }}</div>
              <div class="course-desc">{{ c.description }}</div>
              <div class="course-meta">
                <span>{{ c.duration_min }} 分钟</span>
                <span>{{ c.completed ? '已完成' : `${c.enroll_count || 0} 人参与` }}</span>
              </div>
              <div v-if="c.attachment_name" class="course-attach">
                <el-icon><Document /></el-icon>
                <a :href="`/api/training/download/${c.id}`" target="_blank" @click.stop>{{ c.attachment_name }}</a>
              </div>
            </div>
            <div class="course-actions">
              <el-button v-if="!c.completed" type="primary" size="small" @click="startCourse(c)">开始学习</el-button>
              <el-tag v-else type="success" size="small">已学完</el-tag>
              <template v-if="isSecops">
                <el-button size="small" @click="openCourse(c)">编辑</el-button>
                <el-button size="small" type="danger" plain @click="removeCourse(c)">删除</el-button>
              </template>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 我的学习记录 -->
    <div v-if="tab === 'progress'">
      <el-table :data="progress" stripe>
        <el-table-column prop="course_title" label="课程" min-width="200" />
        <el-table-column prop="started_at" label="开始时间" width="160">
          <template #default="{ row }">{{ fmt(row.started_at) }}</template>
        </el-table-column>
        <el-table-column prop="completed_at" label="完成时间" width="160">
          <template #default="{ row }">{{ row.completed_at ? fmt(row.completed_at) : '—' }}</template>
        </el-table-column>
        <el-table-column prop="score" label="得分" width="90">
          <template #default="{ row }">{{ row.score ?? '—' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><el-tag :type="row.completed_at ? 'success' : 'info'" size="small">{{ row.completed_at ? '已完成' : '学习中' }}</el-tag></template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 题库管理（专家） -->
    <div v-if="tab === 'questions' && isSecops">
      <el-table :data="questions" stripe>
        <el-table-column prop="question" label="题目" min-width="260" show-overflow-tooltip />
        <el-table-column prop="category" label="分类" width="120" />
        <el-table-column prop="course_id" label="所属课程" width="100">
          <template #default="{ row }">{{ courseName(row.course_id) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button link type="danger" size="small" @click="removeQuestion(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 我的考试 -->
    <div v-if="tab === 'exams'">
      <el-table :data="myExams" stripe>
        <el-table-column prop="title" label="考试" min-width="200" />
        <el-table-column prop="course_title" label="所属课程" min-width="140">
          <template #default="{ row }">{{ row.course_title || '通用测验' }}</template>
        </el-table-column>
        <el-table-column prop="total_score" label="得分" width="90">
          <template #default="{ row }">{{ row.total_score ?? '—' }}</template>
        </el-table-column>
        <el-table-column prop="started_at" label="开始时间" width="160">
          <template #default="{ row }">{{ fmt(row.started_at) }}</template>
        </el-table-column>
        <el-table-column prop="submitted_at" label="提交时间" width="160">
          <template #default="{ row }">{{ row.submitted_at ? fmt(row.submitted_at) : '—' }}</template>
        </el-table-column>
        <el-table-column label="结果" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.status === 'passed'" type="success" size="small">通过</el-tag>
            <el-tag v-else-if="row.status === 'failed'" type="danger" size="small">未通过</el-tag>
            <el-tag v-else type="info" size="small">进行中</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 培训统计（专家） -->
    <div v-if="tab === 'stats' && isSecops">
      <el-table :data="courseStats" stripe>
        <el-table-column prop="course_title" label="课程" min-width="200" />
        <el-table-column prop="category" label="分类" width="110" />
        <el-table-column prop="enroll_count" label="参与人数" width="90" align="center" />
        <el-table-column prop="completed_count" label="完成人数" width="90" align="center" />
        <el-table-column label="完成率" width="90" align="center">
          <template #default="{ row }">{{ row.completion_rate }}%</template>
        </el-table-column>
        <el-table-column prop="avg_score" label="平均分" width="90" align="center" />
        <el-table-column prop="exam_count" label="考试次数" width="90" align="center" />
        <el-table-column label="考试通过率" width="100" align="center">
          <template #default="{ row }">{{ row.exam_pass_rate }}%</template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 课程编辑弹窗 -->
    <el-dialog v-model="courseVisible" :title="courseForm.id ? '编辑课程' : '新建课程'" width="560px">
      <el-form :model="courseForm" label-width="80px">
        <el-form-item label="标题"><el-input v-model="courseForm.title" /></el-form-item>
        <el-form-item label="分类">
          <el-select v-model="courseForm.category" placeholder="请选择分类" style="width:100%">
            <el-option label="安全意识" value="安全意识" />
            <el-option label="开发安全" value="开发安全" />
            <el-option label="应急响应" value="应急响应" />
            <el-option label="合规审计" value="合规审计" />
            <el-option label="数据安全" value="数据安全" />
            <el-option label="密码安全" value="密码安全" />
            <el-option label="移动安全" value="移动安全" />
            <el-option label="云安全" value="云安全" />
          </el-select>
        </el-form-item>
        <el-form-item label="时长(分)"><el-input-number v-model="courseForm.duration" :min="1" /></el-form-item>
        <el-form-item label="简介"><el-input v-model="courseForm.description" type="textarea" :rows="3" /></el-form-item>
        <el-form-item label="内容">
          <el-input v-model="courseForm.content" type="textarea" :rows="4" placeholder="课程正文（Markdown）" />
        </el-form-item>
        <el-form-item label="附件">
          <el-upload
            :action="null"
            :auto-upload="false"
            :on-change="handleFileChange"
            :on-remove="handleFileRemove"
            :file-list="fileList"
            :limit="1"
            accept=".ppt,.pptx,.pdf,.doc,.docx,.mp4,.mov,.avi,.mkv,.zip,.rar"
          >
            <el-button type="primary" plain><el-icon><Upload /></el-icon> 选择文件</el-button>
            <template #tip><div class="upload-tip">支持 PPT / PDF / Word / 视频 / 压缩包</div></template>
          </el-upload>
        </el-form-item>
        <el-form-item label="发布">
          <el-switch v-model="courseForm.is_published" />
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="courseVisible = false">取消</el-button><el-button type="primary" @click="saveCourse">保存</el-button></template>
    </el-dialog>

    <!-- 课程学习弹窗 -->
    <el-dialog v-model="learnVisible" :title="`学习：${currentCourse?.title}`" width="800px" :close-on-click-modal="false">
      <div v-if="currentCourse" class="learn-body">
        <div class="learn-meta">
          <el-tag size="small">{{ currentCourse.category }}</el-tag>
          <span>{{ currentCourse.duration_min }} 分钟</span>
        </div>
        <div v-if="currentCourse.content" class="learn-content">
          <pre>{{ currentCourse.content }}</pre>
        </div>
        <div v-if="currentCourse.attachment_name || currentCourse.attachment_path" class="learn-attach">
          <el-icon><Document /></el-icon>
          <span>附件：{{ currentCourse.attachment_name || '课程附件' }}</span>
          <el-button type="primary" size="small" @click="openAttachment">在线查看</el-button>
        </div>
        <div v-if="!currentCourse.content && !currentCourse.attachment_name && !currentCourse.attachment_path" class="learn-empty">
          <el-empty description="该课程暂无内容，请直接标记完成" />
        </div>
      </div>
      <template #footer>
        <el-button @click="learnVisible = false">关闭</el-button>
        <el-button type="primary" @click="completeLearning">我已完成学习</el-button>
      </template>
    </el-dialog>

    <!-- 随堂测验弹窗 -->
    <el-dialog v-model="examVisible" :title="exam?.title || '随堂测验'" width="720px" :close-on-click-modal="false" :close-on-press-escape="false">
      <!-- 答题中 -->
      <div v-if="!examResult">
        <div class="exam-tip">共 {{ examQuestions.length }} 题，每题得分自动计算，满分 100，60 分及格。</div>
        <div v-for="(q, qi) in examQuestions" :key="q.id" class="exam-question">
          <div class="exam-q-title"><span class="exam-q-index">{{ qi + 1 }}.</span> {{ q.question }}</div>
          <div class="exam-options">
            <el-radio-group v-if="q.type === 'single'" v-model="examAnswers[q.id]" class="exam-radio">
              <el-radio v-for="(opt, oi) in parseOptions(q.options)" :key="oi" :value="String.fromCharCode(65 + oi)">
                {{ String.fromCharCode(65 + oi) }}. {{ opt }}
              </el-radio>
            </el-radio-group>
          </div>
        </div>
      </div>
      <!-- 结果展示 -->
      <div v-else class="exam-result">
        <div class="result-icon" :class="examResult.status === 'passed' ? 'passed' : 'failed'">
          <el-icon :size="48"><component :is="examResult.status === 'passed' ? 'SuccessFilled' : 'CircleCloseFilled'" /></el-icon>
        </div>
        <div class="result-title">{{ examResult.status === 'passed' ? '考试通过' : '考试未通过' }}</div>
        <div class="result-score">
          <span class="score-num">{{ examResult.total_score }}</span>
          <span class="score-total"> / 100</span>
        </div>
        <div class="result-detail">及格线：{{ examResult.pass_score }} 分</div>
      </div>
      <template #footer>
        <template v-if="!examResult">
          <el-button @click="examVisible = false">取消</el-button>
          <el-button type="primary" :loading="submittingExam" @click="submitExam">交卷</el-button>
        </template>
        <template v-else>
          <el-button type="primary" @click="closeExam">确定</el-button>
        </template>
      </template>
    </el-dialog>

    <!-- 新增题目 -->
    <el-dialog v-model="qVisible" title="新增题目" width="520px">
      <el-form :model="qForm" label-width="80px">
        <el-form-item label="题目"><el-input v-model="qForm.question" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="分类"><el-input v-model="qForm.category" /></el-form-item>
        <el-form-item v-for="(_, i) in options" :key="i" :label="`选项${i + 1}`">
          <div class="qopt">
            <el-input v-model="qForm.options[i]" />
            <el-checkbox v-model="qForm.correct[i]">正确</el-checkbox>
          </div>
        </el-form-item>
        <el-form-item label="所属课程">
          <el-select v-model="qForm.course_id" clearable placeholder="通用（不属课程）">
            <el-option v-for="c in allCourses" :key="c.id" :label="c.title" :value="c.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="qVisible = false">取消</el-button><el-button type="primary" @click="saveQuestion">保存</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Upload, Document, SuccessFilled, CircleCloseFilled } from '@element-plus/icons-vue'
import { trainingApi } from '../api'
import { useUserStore } from '../store/user'

const route = useRoute()
const store = useUserStore()
const isSecops = computed(() => ['admin', 'secops'].includes(store.role))
const tab = computed(() => {
  const p = route.path
  if (p.includes('/progress')) return 'progress'
  if (p.includes('/questions')) return 'questions'
  if (p.includes('/exams')) return 'exams'
  if (p.includes('/stats')) return 'stats'
  return 'courses'
})
const pageTitle = computed(() => {
  const titles = { courses: '课程中心', progress: '我的进度', questions: '题库管理', exams: '在线考试', stats: '培训统计' }
  return titles[tab.value] || '课程中心'
})
const courses = ref([])
const allCourses = ref([])
const progress = ref([])
const questions = ref([])

const courseVisible = ref(false)
const courseForm = reactive({ id: null, title: '', category: '', duration: 30, description: '', content: '', attachment_path: null, attachment_name: null, is_published: true })
const fileList = ref([])
const qVisible = ref(false)
const qForm = reactive({ question: '', category: '', options: ['', '', '', ''], correct: [false, false, false, false], course_id: null })
const options = [0, 1, 2, 3]

const learnVisible = ref(false)
const currentCourse = ref(null)
const learnScore = ref('')

// 考试状态
const examVisible = ref(false)
const exam = ref(null)
const examQuestions = ref([])
const examAnswers = ref({})
const examResult = ref(null)      // 考试结果（提交后展示）
const myExams = ref([])
const courseStats = ref([])
const submittingExam = ref(false)

function fmt(d) { return d ? d.replace('T', ' ').slice(0, 16) : '' }
function courseName(id) { return allCourses.value.find((c) => c.id === id)?.title || '通用' }
function parseOptions(str) {
  if (!str) return []
  try {
    const arr = JSON.parse(str)
    return Array.isArray(arr) ? arr : []
  } catch {
    return str.split('\n').map((s) => s.trim()).filter(Boolean)
  }
}

async function loadCourses() { courses.value = (await trainingApi.courses()).data }
async function loadProgress() { progress.value = (await trainingApi.progress()).data }
async function loadQuestions() { questions.value = (await trainingApi.questions()).data }
async function loadExams() { myExams.value = (await trainingApi.myExams()).data }
async function loadStats() { if (isSecops.value) courseStats.value = (await trainingApi.courseStats()).data }
async function loadAll() { if (isSecops.value) { allCourses.value = (await trainingApi.coursesAll()).data } else { allCourses.value = courses.value } }

function openCourse(c) {
  if (c) {
    Object.assign(courseForm, { id: c.id, title: c.title, category: c.category, duration: c.duration_min, description: c.description, content: c.content, attachment_path: c.attachment_path || null, attachment_name: c.attachment_name || null, is_published: !!c.is_published })
    fileList.value = c.attachment_name ? [{ name: c.attachment_name, url: c.attachment_path }] : []
  } else {
    Object.assign(courseForm, { id: null, title: '', category: '', duration: 30, description: '', content: '', attachment_path: null, attachment_name: null, is_published: true })
    fileList.value = []
  }
  courseVisible.value = true
}

function handleFileChange(file) {
  // el-upload on-change：把新文件替换到 fileList
  fileList.value = [file]
}

function handleFileRemove() {
  courseForm.attachment_path = null
  courseForm.attachment_name = null
}

async function saveCourse() {
  try {
    // 如果有新文件，先上传
    const rawFile = fileList.value[0]?.raw
    if (rawFile) {
      const formData = new FormData()
      formData.append('file', rawFile)
      const res = await trainingApi.uploadFile(formData)
      courseForm.attachment_path = res.data.path
      courseForm.attachment_name = res.data.filename
    }
    if (courseForm.id) await trainingApi.updateCourse(courseForm.id, courseForm)
    else await trainingApi.createCourse(courseForm)
    ElMessage.success('已保存'); courseVisible.value = false; loadCourses(); loadAll()
  } catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}
async function removeCourse(c) {
  await ElMessageBox.confirm(`删除课程「${c.title}」？`, '提示', { type: 'warning' })
  await trainingApi.removeCourse(c.id); loadCourses()
}
async function startCourse(c) {
  await trainingApi.startCourse(c.id)
  currentCourse.value = c
  learnScore.value = ''
  learnVisible.value = true
}
function openAttachment() {
  if (!currentCourse.value) return
  const name = (currentCourse.value.attachment_name || '').toLowerCase()
  const url = `/api/training/download/${currentCourse.value.id}`
  const ext = name.split('.').pop()
  // 图片：直接弹窗预览
  if (['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'].includes(ext)) {
    ElImageViewer({ urlList: [url] })
    return
  }
  // 视频：弹窗内嵌播放
  if (['mp4', 'mov', 'avi', 'mkv', 'webm'].includes(ext)) {
    ElMessageBox.alert(`<video src="${url}" controls autoplay style="width:100%;max-height:60vh"></video>`, '在线播放', {
      dangerouslyUseHTMLString: true,
      customStyle: 'min-width: 600px',
    })
    return
  }
  // PDF：弹窗内嵌预览
  if (ext === 'pdf') {
    ElMessageBox.alert(`<iframe src="${url}" style="width:100%;height:60vh;border:0"></iframe>`, '在线预览', {
      dangerouslyUseHTMLString: true,
      customStyle: 'min-width: 600px',
    })
    return
  }
  // PPT / Word / 压缩包等浏览器无法直接预览：使用 Office Online Viewer
  // 仅对 .ppt/.pptx/.doc/.docx 生效
  if (['ppt', 'pptx', 'doc', 'docx'].includes(ext)) {
    const viewer = `https://view.officeapps.live.com/op/embed.aspx?src=${encodeURIComponent(window.location.origin + url)}`
    window.open(viewer, '_blank')
    return
  }
  // 其他类型（zip/rar 等）：回退到下载
  window.open(url, '_blank')
}
async function completeLearning() {
  try {
    await ElMessageBox.confirm('确认已完成该课程学习？接下来进入随堂测验。', '确认完成', { type: 'info' })
    await trainingApi.completeCourse(currentCourse.value.id)
    learnVisible.value = false
    ElMessage.success('学习完成，即将开始随堂测验')
    loadCourses(); loadProgress()
    await startExam(currentCourse.value.id)
  } catch (e) {
    // 用户取消确认框时不报错
    if (e === 'cancel') return
    // 题库为空等后端错误
    const msg = e.response?.data?.detail || e.message || '操作失败'
    if (msg !== '操作失败') ElMessage.warning(msg)
  }
}

async function startExam(courseId) {
  // 生成并获取考试题目
  const created = await trainingApi.createExam({ course_id: courseId })
  exam.value = created.data
  const qs = await trainingApi.examQuestions(exam.value.id)
  examQuestions.value = qs.data
  examAnswers.value = {}
  examResult.value = null
  examVisible.value = true
}

async function submitExam() {
  if (submittingExam.value) return
  // 校验是否已作答全部题目
  const unanswered = examQuestions.value.filter((q) => !examAnswers.value[q.id])
  if (unanswered.length) {
    ElMessage.warning(`还有 ${unanswered.length} 题未作答`)
    return
  }
  submittingExam.value = true
  try {
    const res = await trainingApi.submitExam(exam.value.id, { answers: examAnswers.value })
    examResult.value = res.data
    loadExams(); loadProgress()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '提交失败')
  } finally {
    submittingExam.value = false
  }
}

function closeExam() {
  examVisible.value = false
  examResult.value = null
  examQuestions.value = []
  loadCourses()
}
async function saveQuestion() {
  const correctIdx = qForm.correct.map((v, i) => (v ? i : -1)).filter((i) => i >= 0)
  const payload = { question: qForm.question, category: qForm.category, options: qForm.options, correct: correctIdx[0] ?? 0, course_id: qForm.course_id }
  try { await trainingApi.createQuestion(payload); ElMessage.success('已保存'); qVisible.value = false; loadQuestions() }
  catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}
async function removeQuestion(row) {
  await ElMessageBox.confirm('删除该题目？', '提示', { type: 'warning' })
  await trainingApi.removeQuestion(row.id); loadQuestions()
}

onMounted(async () => { loadCourses(); loadProgress(); loadExams(); loadAll(); if (isSecops.value) { loadQuestions(); loadStats() } })
</script>

<style scoped>
.course-card { margin-bottom: 16px; }
.course-cat { font-size: 12px; color: #3b82f6; font-weight: 600; }
.course-title { font-size: 16px; font-weight: 700; margin: 6px 0; color: #0f172a; }
.course-desc { font-size: 13px; color: #64748b; height: 40px; overflow: hidden; }
.course-meta { font-size: 12px; color: #94a3b8; margin-top: 8px; display: flex; justify-content: space-between; }
.course-actions { margin-top: 12px; display: flex; gap: 8px; }
.tab-head { display: flex; justify-content: space-between; margin-bottom: 14px; }
.qopt { display: flex; gap: 10px; width: 100%; align-items: center; }
.upload-tip { font-size: 12px; color: #94a3b8; margin-top: 4px; }
.course-attach { font-size: 12px; color: #3b82f6; margin-top: 6px; display: flex; align-items: center; gap: 4px; }
.course-attach a { color: #3b82f6; text-decoration: none; }
.course-attach a:hover { text-decoration: underline; }
.learn-body { max-height: 500px; overflow-y: auto; }
.learn-meta { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; color: #64748b; font-size: 13px; }
.learn-content { background: #f8fafc; padding: 16px; border-radius: 8px; margin-bottom: 16px; }
.learn-content pre { white-space: pre-wrap; word-break: break-word; margin: 0; font-family: inherit; font-size: 14px; color: #334155; line-height: 1.7; }
.learn-attach { display: flex; align-items: center; gap: 8px; padding: 12px; background: #eff6ff; border-radius: 6px; color: #1e40af; font-size: 13px; }
.learn-empty { padding: 20px 0; }
.exam-tip { background: #f0f9ff; color: #0369a1; padding: 10px 12px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; }
.exam-question { padding: 14px 0; border-bottom: 1px dashed #e2e8f0; }
.exam-q-title { font-size: 15px; color: #1e293b; font-weight: 600; margin-bottom: 10px; }
.exam-q-index { color: #3b82f6; }
.exam-options { padding-left: 20px; }
.exam-radio { display: flex; flex-direction: column; gap: 8px; align-items: flex-start; }
.exam-result { text-align: center; padding: 20px 0; }
.result-icon { font-size: 48px; margin-bottom: 12px; }
.result-icon.passed { color: #10b981; }
.result-icon.failed { color: #ef4444; }
.result-title { font-size: 20px; font-weight: 700; color: #0f172a; margin-bottom: 12px; }
.result-score { margin: 8px 0; }
.score-num { font-size: 56px; font-weight: 800; color: #3b82f6; }
.score-total { font-size: 22px; color: #94a3b8; }
.result-detail { color: #64748b; font-size: 14px; }
</style>
