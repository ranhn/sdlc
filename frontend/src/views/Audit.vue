<template>
  <div class="audit">
    <div class="page-header">
      <span class="page-title">审计日志</span>
      <el-form inline>
        <el-form-item label="操作人"><el-input v-model="filters.operator" placeholder="姓名/用户名" clearable style="width: 160px" @keyup.enter="load" /></el-form-item>
        <el-form-item label="操作类型"><el-input v-model="filters.action" placeholder="如 create_vuln" clearable style="width: 160px" @keyup.enter="load" /></el-form-item>
        <el-form-item><el-button type="primary" @click="load">查询</el-button></el-form-item>
      </el-form>
    </div>

    <el-card shadow="never">
      <el-table :data="list" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="username" label="操作人" width="130" />
        <el-table-column prop="action" label="操作" width="160" />
        <el-table-column prop="module" label="模块" width="110" />
        <el-table-column prop="detail" label="详情" min-width="280" show-overflow-tooltip />
        <el-table-column prop="created_at" label="时间" width="170">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
      </el-table>
      <el-pagination v-model:current-page="filters.page" :page-size="filters.page_size" :total="total"
        layout="total, prev, pager, next" background class="pager" @current-change="load" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { http } from '../api'

const list = ref([])
const total = ref(0)
const loading = ref(false)
const filters = reactive({ operator: '', action: '', page: 1, page_size: 20 })

function fmt(d) { return d ? d.replace('T', ' ').slice(0, 19) : '' }

async function load() {
  loading.value = true
  try {
    const params = { page: filters.page, page_size: filters.page_size }
    if (filters.operator) params.operator = filters.operator
    if (filters.action) params.action = filters.action
    const res = await http.get('/logs', { params })
    list.value = res.data.items || res.data.logs || []
    total.value = res.data.total || 0
  } finally { loading.value = false }
}
onMounted(load)
</script>

<style scoped>
.pager { margin-top: 16px; justify-content: flex-end; }
</style>
