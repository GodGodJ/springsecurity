package com.example.springsecurity.controller;

import org.omg.CORBA.PUBLIC_MEMBER;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/tasks")
public class TaskController {

    @GetMapping
    public String listTasks(){
        return "任务列表";
    }

    @PostMapping
    public String newTasks(){
        return "创建了一个新的任务";
    }

    @PutMapping("/{taskId}")
    public String updateTasks(@PathVariable("taskId")Integer id){
        return "更新了一下id为:"+id+"的任务";
    }

    @DeleteMapping("{taskId}")
    public String deleteTasks(@PathVariable("taskId")Integer id){
        return "删除了id为:"+id+"的任务";
    }

    @RequestMapping("/index")
    public String index(){
        return "cnmd";
    }

    @RequestMapping("/dnmd")
    public String dnmd(){
        return "dnmd";
    }

}
