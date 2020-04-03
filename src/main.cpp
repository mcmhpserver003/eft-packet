#include "pcap++/IPv4Layer.h"
#include "pcap++/IPv6Layer.h"
#include "pcap++/Packet.h"
#include "pcap++/PcapLiveDevice.h"
#include "pcap++/PcapLiveDeviceList.h"
#include "pcap++/UdpLayer.h"

#include "gl/glew.h"
#include "gl/glu.h"
#include "glm/glm.hpp"
#include "glm/gtc/matrix_transform.hpp"
#include "glm/gtx/norm.hpp"
#include "glm/gtc/type_ptr.hpp"
#include "glm/gtx/string_cast.hpp"

#include "SDL/SDL.h"
#include "SDL/SDL_opengl.h"
#include "SDL/SDL_syswm.h"
#include "unet.hpp"
#include "common.hpp"

#include "tk.hpp"
#include "tk_net.hpp"

#include <mutex>
#include <memory>
#include <thread>
#include <unordered_map>

#define GLT_IMPLEMENTATION
#include "gltext.h"


#include <iostream>
#include <vector>
#include <algorithm>




struct Packet
{
    int timestamp;
    bool outbound;
    std::vector<uint8_t> data;
    std::string src_ip;
    std::string dst_ip;
};

struct WorkGroup
{
    std::mutex work_guard;
    std::vector<Packet> work;
};

struct GraphicsState
{
    SDL_GLContext ctx;
    SDL_Window* window;

    GLuint shader;
    GLuint vao;
    GLuint vbo;
    GLuint line_vao;
    GLuint line_vbo;

    int width;
    int height;
};

std::mutex g_world_lock;

void do_net(std::vector<Packet> work, const char* packet_dump_path);
void do_update();
void do_render(GraphicsState* state);

GraphicsState make_gfx(SDL_GLContext ctx, SDL_Window* window);
void resize_gfx(GraphicsState* state, int width, int height);

//declaring vars and functions used for EFTRadarSettings.ini
void EFTRadarSettup();
bool MakeWindowTransparent(SDL_Window* window, COLORREF colorKey);
std::string DEVICE_IP_RADAR_PC;
std::string DEVICE_IP_GAME_PC;
bool background_Transparent;
bool custom_bg_colour;
int custom_r;
int custom_g;
int custom_b;
int view_mode;
void printviewmode(int vm);

//declaring vars for camera controlls
void KeyController(SDL_KeyboardEvent* key);
glm::vec3 getStrafeVectorRight(glm::vec3 vec);
glm::vec3 freecam_at;
glm::vec3 player_forward_vec;
float movment_sensitivity = 1.0f;
bool freecam = false;
float player_pos_x;
float player_pos_y;
float player_pos_z;
float freecam_pos_x;
float freecam_pos_y = 1.5f;
float freecam_pos_z;
float topdown_cam_height = 10.0f;
float topdown_freecam_pos_x;
float topdown_freecam_pos_z;


int main(int argc, char* argv[])
{
    //Setup EFTRadar using EFTRadarSettings.ini
    EFTRadarSettup();

    const char* packet_dump_path = argc >= 2 ? argv[1] : nullptr;
    bool dump_packets = argc >= 3 && argv[2][0] == '1';

    static int s_base_time = GetTickCount();
    static float time_scale = argc >= 4 ? atof(argv[3]) : 1.0f;

    std::unique_ptr<std::thread> processing_thread;
    pcpp::PcapLiveDevice* dev = nullptr;

    WorkGroup work;
    if (packet_dump_path && !dump_packets)
    {
        // We load packets for offline replay on another thread.
        processing_thread = std::make_unique<std::thread>(
            [packet_dump_path, &work]()
            {
                FILE* file = fopen(packet_dump_path, "rb");

                bool outbound;
                while (fread(&outbound, sizeof(outbound), 1, file) == 1)
                {
                    int timestamp;
                    fread(&timestamp, 4, 1, file);

                    int size;
                    fread(&size, 4, 1, file);

                    std::vector<uint8_t> packet;
                    packet.resize(size);
                    fread(packet.data(), size, 1, file);

                    static int s_first_packet_time = timestamp;

                    while ((GetTickCount() - s_base_time) * time_scale < (uint32_t)timestamp - s_first_packet_time)
                    {
                        std::this_thread::yield(); // sleep might be better? doesn't matter much
                    }

                    std::lock_guard<std::mutex> lock(work.work_guard);
                    work.work.push_back({ timestamp, outbound, std::move(packet) });
                }

                fclose(file);
            });
    }
    else
    {
        
        dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(DEVICE_IP_RADAR_PC.c_str());
        //open fails with wrong ip
        if (dev == NULL)
        {
            std::cout << "Cannot find interface with IPv4 address of: '" << DEVICE_IP_RADAR_PC.c_str() << "' on Radar PC\n";
            std::cout << "Press ENTER to exit \n";
            std::cin.ignore();
            exit(1);
        }
        dev->open();
        
        

        pcpp::ProtoFilter filter(pcpp::UDP);

        dev->setFilter(filter);

        static std::string s_server_ip;
        dev->startCapture(
            [](pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* user_data)
            {
                pcpp::Packet parsed(packet);

                std::string src_ip;
                std::string dst_ip;

                if (pcpp::IPv4Layer* ip = parsed.getLayerOfType<pcpp::IPv4Layer>())
                {
                    src_ip = ip->getSrcIpAddress().toString();
                    dst_ip = ip->getDstIpAddress().toString();
                }
                else if (pcpp::IPv6Layer* ip = parsed.getLayerOfType<pcpp::IPv6Layer>())
                {
                    src_ip = ip->getSrcIpAddress().toString();
                    dst_ip = ip->getDstIpAddress().toString();
                }

                pcpp::UdpLayer* udp = parsed.getLayerOfType<pcpp::UdpLayer>();
                int len = udp->getDataLen() - udp->getHeaderLen();
                uint8_t* data_start = udp->getDataPtr(udp->getHeaderLen());

                int timestamp = (int)(GetTickCount() - s_base_time);
                bool outbound = src_ip == DEVICE_IP_GAME_PC;
                std::vector<uint8_t> data;
                data.resize(len);
                memcpy(data.data(), data_start, len);

                WorkGroup& work = *(WorkGroup*)user_data;
                std::lock_guard<std::mutex> lock(work.work_guard);
                work.work.push_back({ timestamp , outbound, std::move(data), std::move(src_ip), std::move(dst_ip) });
            }, &work);
    }
    SDL_Init(SDL_INIT_EVERYTHING);

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);


    


    //add for borderless    | SDL_WINDOW_BORDERLESS
    SDL_Window* win = SDL_CreateWindow("Bastian Suter's Queef", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1920, 1080, SDL_WINDOW_OPENGL | SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_MAXIMIZED);
    SDL_GLContext ctx = SDL_GL_CreateContext(win);


    glewInit();
    SDL_GL_SetSwapInterval(1);

    GraphicsState gfx = make_gfx(ctx, win);

    bool quit = false;


    std::unique_ptr<std::thread> net_thread = std::make_unique<std::thread>(
        [&]()
        {
            while (!quit)
            {
                std::vector<Packet> local_work;

                {
                    std::lock_guard<std::mutex> lock(work.work_guard);
                    std::swap(local_work, work.work);
                }

                if (!local_work.empty())
                {
                    do_net(std::move(local_work), dump_packets ? packet_dump_path : nullptr);
                }
                else
                {
                    SDL_Delay(10);
                }
            }
        });

    while (!quit)
    {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            switch (e.type) {

            case SDL_KEYDOWN:
            case SDL_KEYUP:
                    KeyController(&e.key);
                break;


            //window closed
            case SDL_QUIT: 
                quit = true;
                break;
            //default case
            default:
                break;
            }
        }




        do_update();
        //only call function if transparent true
        if(background_Transparent){
            MakeWindowTransparent(win, RGB(255, 0, 255));
        }
        do_render(&gfx);
    }

    net_thread->join();
    gltTerminate();

    SDL_GL_DeleteContext(ctx);
    SDL_DestroyWindow(win);

    if (processing_thread)
    {
        processing_thread->join();
    }

    if (dev)
    {
        dev->stopCapture();
        dev->close();
    }

    return 0;
}

struct FragmentedMessage
{
    int parts;
    std::vector<std::unique_ptr<std::vector<uint8_t>>> packets;
};

static std::unordered_map<int, FragmentedMessage> messages;

void do_net(std::vector<Packet> work, const char* packet_dump_path)
{
    auto write_packet = [packet_dump_path](Packet& packet)
    {
        if (packet_dump_path)
        {
            FILE* file = fopen(packet_dump_path, "ab");
            fwrite(&packet.outbound, sizeof(packet.outbound), 1, file);
            fwrite(&packet.timestamp, 4, 1, file);
            int len = (int)packet.data.size();
            fwrite(&len, 4, 1, file);
            fwrite(packet.data.data(), len, 1, file);
            fclose(file);
        }
    };

    static std::unique_ptr<UNET::AcksCache> s_inbound_acks;
    static std::unique_ptr<UNET::AcksCache> s_outbound_acks; // Technically it would be better to read acks from recieved packets for outbound

    for (Packet& packet : work)
    {
        if (packet.data.size() <= 3)
        {
            // Too short for us to care about. Proceed.
            continue;
        }

        uint8_t* data_start = packet.data.data();
        int data_len = (int)packet.data.size();

        if (uint16_t conn_id = UNET::decodeConnectionId(data_start); !conn_id)
        {
            // This is a system message. We don't want to process it.
            if (data_start[2] == UNET::kConnect)
            {
                s_inbound_acks = std::make_unique<UNET::AcksCache>("INBOUND");
                s_outbound_acks = std::make_unique<UNET::AcksCache>("OUTBOUND");

                std::lock_guard<std::mutex> lock(g_world_lock);

                // This is a connection attempt. Let's establish a state.
                tk::g_state = std::make_unique<tk::GlobalState>();
                tk::g_state->server_ip = packet.dst_ip.empty() ? "LOCAL_REPLAY" : packet.dst_ip;
                tk::g_state->loot_db = std::make_unique<tk::LootDatabase>("items.json");
            }

            write_packet(packet);
            continue;
        }

        bool no_state = tk::g_state == nullptr;
        bool no_server = no_state || tk::g_state->server_ip.empty();
        bool filtered_out = no_server ||
            (   tk::g_state->server_ip != packet.src_ip &&
                tk::g_state->server_ip != packet.dst_ip &&
                tk::g_state->server_ip != "LOCAL_REPLAY");

        if (filtered_out)
        {
            continue;
        }

        write_packet(packet);
        // Now we strip the UNET-isms...

        UNET::NetPacketHeader* packet_hdr = reinterpret_cast<UNET::NetPacketHeader*>(data_start);
        decodeNetPacketHeader(packet_hdr);
        data_start += sizeof(UNET::NetPacketHeader);
        data_len -= sizeof(UNET::NetPacketHeader);

        UNET::PacketAcks128* acks = reinterpret_cast<UNET::PacketAcks128*>(data_start);
        // probably need to decode??
        data_start += sizeof(UNET::PacketAcks128);
        data_len -= sizeof(UNET::PacketAcks128);

        UNET::AcksCache* received_acks = packet.outbound ? s_outbound_acks.get() : s_inbound_acks.get();

        UNET::MessageExtractor messageExtractor((char*)data_start, data_len, 3 + (102*2), received_acks);
        while (messageExtractor.GetNextMessage())
        {
            std::unique_ptr<std::vector<uint8_t>> complete_message;

            {
                uint8_t* user_data = (uint8_t*)messageExtractor.GetMessageStart();
                int user_len = messageExtractor.GetMessageLength();
                int channel = messageExtractor.GetChannelId();

                if (channel == 0 || channel == 1 || channel == 2) // ReliableFragmented
                {
                    UNET::NetMessageFragmentedHeader* hr = reinterpret_cast<UNET::NetMessageFragmentedHeader*>(user_data);
                    UNET::decode(hr);
                    user_data += sizeof(UNET::NetMessageFragmentedHeader);
                    user_len -= sizeof(UNET::NetMessageFragmentedHeader);

                    std::unique_ptr<std::vector<std::uint8_t>> data = std::make_unique<std::vector<std::uint8_t>>();
                    data->resize(user_len);
                    memcpy(data->data(), user_data, user_len);
                    int key = hr->fragmentedMessageId | channel << 8;
                    messages[key].parts = hr->fragmentAmnt;
                    messages[key].packets.resize(hr->fragmentAmnt);

                    if (hr->fragmentIdx >= messages[key].packets.size())
                    {
                        // broken fragment
                    }
                    else
                    {
                        messages[key].packets[hr->fragmentIdx] = std::move(data);
                    }

                    bool complete = true;

                    for (int i = 0; i < hr->fragmentAmnt; ++i)
                    {
                        if (!messages[key].packets[i])
                        {
                            complete = false;
                            break;
                        }
                    }

                    if (complete)
                    {
                        for (int i = 1; i < hr->fragmentAmnt; ++i)
                        {
                            messages[key].packets[0]->insert(
                                std::end(*messages[key].packets[0]),
                                std::begin(*messages[key].packets[i]),
                                std::end(*messages[key].packets[i]));
                        }

                        complete_message = std::move(messages[key].packets[0]);
                        messages.erase(key);
                    }
                }
                else
                {
                    if (channel % 2 == 1)
                    {
                        UNET::NetMessageReliableHeader* hr = reinterpret_cast<UNET::NetMessageReliableHeader*>(user_data);
                        decode(hr);
                        if (!received_acks->ReadMessage(hr->messageId))
                        {
                            continue;
                        }
                    }

                    // channel % 2 == 0 does not have NetMessageReliableHeader but skip same bytes so this works
                    user_data += sizeof(UNET::NetMessageReliableHeader);
                    user_data += sizeof(UNET::NetMessageOrderedHeader);
                    user_len -= sizeof(UNET::NetMessageReliableHeader);
                    user_len -= sizeof(UNET::NetMessageOrderedHeader);
                    complete_message = std::make_unique<std::vector<uint8_t>>();
                    complete_message->resize(user_len);
                    memcpy(complete_message->data(), user_data, user_len);
                }
            }

            if (complete_message)
            {
                tk::ByteStream str(complete_message->data(), (int)complete_message->size());
                tk::process_packet(&str, messageExtractor.GetChannelId(), packet.outbound);
            }
        }
    }
}


void do_update()
{
}
bool testing = true;
void do_render(GraphicsState* gfx)
{
    // ye who read this code, judge its performance (and lack of state caching) not
    std::lock_guard<std::mutex> lock(g_world_lock);

    if (background_Transparent) {
        glClearColor(255, 0, 255, 255);
    }
    else if(custom_bg_colour) {
        glClearColor(custom_r, custom_g, custom_b, 1.0f);
    }
    else{
        glClearColor(0.5f, 0.5f, 0.5f, 1.0f);
    }
    
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    auto draw_box = [&gfx]
    (float x, float y, float z, float scale_x, float scale_y, float scale_z, int r, int g, int b)
    {
        glm::mat4 model = glm::mat4(1.0f);
        glm::vec3 pos(x, y, z);
        model = glm::translate(model, pos) * glm::scale(model, glm::vec3(scale_x, scale_y, scale_z));
        glUseProgram(gfx->shader);
        glUniform1i(glGetUniformLocation(gfx->shader, "line"), 0);
        glUniform1f(glGetUniformLocation(gfx->shader, "obj_y"), y - (scale_y / 2.0f));
        glUniform3f(glGetUniformLocation(gfx->shader, "color"), r / 255.0f, g / 255.0f, b / 255.0f);
        glUniformMatrix4fv(glGetUniformLocation(gfx->shader, "model"), 1, GL_FALSE, &model[0][0]);
        glBindVertexArray(gfx->vao);
        glBindBuffer(GL_ARRAY_BUFFER, gfx->vbo);
        glDrawArrays(GL_TRIANGLES, 0, 36);
    };

    if (testing) {

    }else{

    if (tk::g_state && tk::g_state->map)
    {
        glm::mat4 view = glm::mat4(1.0f);
        glm::mat4 projection = glm::mat4(1.0f);

        projection = glm::perspective(glm::radians(75.0f), (float)gfx->width / (float)gfx->height, 0.1f, 2000.0f);

        // flip x axis, from right handed (gl) to left handed (unity)
        projection = glm::scale(projection, glm::vec3(-1.0f, 1.0f, 1.0f));

        auto get_forward_vec = [](float pitch, float yaw, glm::vec3 pos)
        {
            float elevation = glm::radians(-pitch);
            float heading = glm::radians(yaw);
            glm::vec3 forward_vec(cos(elevation) * sin(heading), sin(elevation), cos(elevation) * cos(heading));
            return forward_vec;
        };

        auto get_alpha_for_y = [](float y1, float y2)
        {
            if (!background_Transparent) {
                return abs(y1 - y2) >= 3.0f ? 63 : 255;
            }
            return 255;
        };


        tk::g_state->map->lock();

        float player_y = 0.0f;
        //glm::vec3 player_forward_vec;
        glm::vec3 global_downwards_vector = glm::vec3(0.0f, -0.95f, 0.0f);

        if (tk::Observer* player = tk::g_state->map->get_player_manual_lock(); player)
        {
            player_pos_x = player->pos.x;
            player_pos_y = player->pos.y;
            player_pos_z = player->pos.z;
            player_y = player->pos.y;
            float pitch = player->rot.y;
            float yaw = player->rot.x;

            //normal playercam
            glm::vec3 cam_at(player_pos_x, player_pos_y +1.5f, player_pos_z);
            player_forward_vec = get_forward_vec(pitch, yaw, cam_at);
            glm::vec3 cam_look = cam_at + player_forward_vec;
            //freecam
            glm::vec3 freecam_at(freecam_pos_x, freecam_pos_y, freecam_pos_z);
            glm::vec3 freecam_look = freecam_at + player_forward_vec;
            //2D / top down fixed 2 player
            glm::vec3 topdown_cam_at(player_pos_x, topdown_cam_height, player_pos_z);
            glm::vec3 topdown_cam_look = topdown_cam_at + player_forward_vec;

            switch (view_mode) {
            case 0:
                view = glm::lookAt(cam_at, cam_look, { 0.0f, 1.0f, 0.0f });
                freecam_pos_x = player_pos_x;
                freecam_pos_y = player_pos_y + 1.5f;
                freecam_pos_z = player_pos_z;
                break;
            case 1:
                view = glm::lookAt(freecam_at, freecam_look, { 0.0f, 1.0f, 0.0f });
                std::cout << "view: " << glm::to_string(view) << "\n";
                std::cout << "cam_at: " << glm::to_string(freecam_at) << "\n";
                std::cout << "freecam_look: " << glm::to_string(freecam_look) << "\n";
                break;
            case 2:
                view = glm::mat4(-1.0f,0.0f,-0.0f,0.0f,0.0f,0.0f,1.0f,0.0f,0.0f,1.0f,-0.0f,0.0f,player_pos_x,-player_pos_z,-topdown_cam_height,1.0f);
                freecam_pos_x = player_pos_x;
                freecam_pos_z = player_pos_z;
                break;
            case 3:
                view = glm::mat4(-1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, freecam_pos_x, -freecam_pos_z, -topdown_cam_height, 1.0f);
                break;

            default:
                view = glm::lookAt(cam_at, cam_look, { 0.0f, 1.0f, 0.0f });
                std::cout << "view_mode incorrect number: " << view_mode << "\n";
                break;
            }
            

            glUseProgram(gfx->shader);
            glUniform1f(glGetUniformLocation(gfx->shader, "player_y"), player_y);
            glUniformMatrix4fv(glGetUniformLocation(gfx->shader, "projection"), 1, GL_FALSE, &projection[0][0]);
            glUniformMatrix4fv(glGetUniformLocation(gfx->shader, "view"), 1, GL_FALSE, &view[0][0]);

            auto draw_text = [&gfx]
                (float x, float y, float z, float scale, const char* txt, int r, int g, int b, int a, glm::mat4* view, glm::mat4* proj)
            {
                GLTtext* text = gltCreateText();
                gltSetText(text, txt);
                gltBeginDraw();
                gltColor(r / 255.0f, g / 255.0f, b / 255.0f, a / 255.0f);
                gltDrawText3D(text, x, y, z, scale, (GLfloat*)&view[0][0], (GLfloat*)&proj[0][0]);
                gltDeleteText(text);
            };

            auto draw_box = [&gfx]
                (float x, float y, float z, float scale_x, float scale_y, float scale_z, int r, int g, int b)
            {
                glm::mat4 model = glm::mat4(1.0f);
                glm::vec3 pos(x, y, z);
                model = glm::translate(model, pos) * glm::scale(model, glm::vec3(scale_x, scale_y, scale_z));
                glUseProgram(gfx->shader);
                glUniform1i(glGetUniformLocation(gfx->shader, "line"), 0);
                glUniform1f(glGetUniformLocation(gfx->shader, "obj_y"), y - (scale_y / 2.0f));
                glUniform3f(glGetUniformLocation(gfx->shader, "color"), r / 255.0f, g / 255.0f, b / 255.0f);
                glUniformMatrix4fv(glGetUniformLocation(gfx->shader, "model"), 1, GL_FALSE, &model[0][0]);
                glBindVertexArray(gfx->vao);
                glBindBuffer(GL_ARRAY_BUFFER, gfx->vbo);
                glDrawArrays(GL_TRIANGLES, 0, 36);
            };

            auto draw_line = [&gfx]
                (float x, float y, float z, float to_x, float to_y, float to_z, int r, int g, int b, int a)
            {
                float vertices[] = {
                    x, y, z,
                    to_x, to_y, to_z,
                };

                glUseProgram(gfx->shader);
                glUniform1i(glGetUniformLocation(gfx->shader, "line"), a);
                glUniform3f(glGetUniformLocation(gfx->shader, "color"), r / 255.0f, g / 255.0f, b / 255.0f);
                glBindBuffer(GL_ARRAY_BUFFER, gfx->line_vbo);
                glBindVertexArray(gfx->line_vao);
                glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STREAM_DRAW);
                glDrawArrays(GL_LINES, 0, 2);
            };

            static std::unordered_map<std::string, std::tuple<uint8_t, uint8_t, uint8_t>> s_group_map; // maybe reset on map change?

            for (tk::Observer* obs : tk::g_state->map->get_observers_manual_lock())
            {
                if (obs->type == tk::Observer::Self)
                {
                    glm::vec3 at(obs->pos.x, obs->pos.y, obs->pos.z);
                    glm::vec3 look = at + (get_forward_vec(obs->rot.y, obs->rot.x, at) * 50.0f);
                    look.y += 1.5f;
                    draw_line(at.x, at.y, at.z, look.x, look.y, look.z, 0, 255, 0, 255);
                    draw_box(at.x, at.y, at.z, 1.0f, 1.0f, 1.0f, 0, 255, 0);
                    continue;
                }

                uint8_t r = 0;
                uint8_t g = 0;
                uint8_t b = 0;

                float scale_x = 1.0f;
                float scale_y = 2.0f;
                float scale_z = 1.0f;

                if (obs->is_unspawned)
                {
                    r = 179;
                    g = 120;
                    b = 211;
                }
                else
                {
                    if (obs->is_dead)
                    {
                        scale_x = 2.0f;
                        scale_y = 1.0f;
                    }

                    if (obs->type == tk::Observer::Scav && obs->is_npc)
                    {
                        r = 255;
                        g = obs->is_dead ? 140 : 255;
                    }
                    else
                    {
                        r = obs->is_dead ? 139 : 255;
                    }
                }

                if (!obs->group_id.empty())
                {
                    if (obs->group_id == player->group_id)
                    {
                        r = 0;
                        g = 255;
                        b = 0;
                    }
                    else if (auto entry = s_group_map.find(obs->group_id); entry == std::end(s_group_map))
                    {
                        s_group_map[obs->group_id] = std::make_tuple(rand() % 256, rand() % 256, rand() % 256);
                    }
                }

                if (!obs->is_dead && !obs->is_unspawned)
                {
                    glm::vec3 at(obs->pos.x, obs->pos.y, obs->pos.z);
                    glm::vec3 enemy_forward_vec = get_forward_vec(obs->rot.y, obs->rot.x, at);
                    bool facing_towards_player = glm::dot(player_forward_vec, enemy_forward_vec) < -0.0f;
                    int alpha = 255;
                    if (!background_Transparent) {
                        alpha = facing_towards_player ? 255 : 63;
                    }
                    glm::vec3 look = at + (enemy_forward_vec * (facing_towards_player ? 75.0f : 12.5f));
                    draw_line(at.x, at.y, at.z, look.x, look.y, look.z, r, g, b, alpha);
                }

                draw_box(obs->pos.x, obs->pos.y, obs->pos.z, scale_x, scale_y, scale_z, r, g, b);
            }

            for (Vector3* pos : tk::g_state->map->get_static_corpses_manual_lock())
            {
                draw_box(pos->x, pos->y, pos->z, 2.0f, 1.0f, 1.0f, 102, 0, 102);
            }

            std::vector<std::pair<Vector3, std::string>> loot_text_to_render;

            auto draw_loot = [&](tk::LootEntry* entry, bool include_equipment = true)
            {
                // This is where you insert your loot highlighting logic.
                draw_box(entry->pos.x, entry->pos.y, entry->pos.z, 0.5f, 0.5f, 0.5f, entry->container ? 255 : 0, entry->container ? 215 : 0, 0);
            };

            for (tk::LootEntry* entry : tk::g_state->map->get_loot_manual_lock())
            {
                draw_loot(entry);
            }

            for (tk::TemporaryLoot* entry : tk::g_state->map->get_temporary_loots_manual_lock())
            {
                draw_box(entry->pos.x, entry->pos.y + 1.5f, entry->pos.z, 0.15f, 3.0f, 0.15f, 0, 200, 200);
                draw_box(entry->pos.x, entry->pos.y, entry->pos.z, 0.25f, 0.25f, 0.25f, 0, 200, 200);
            }

            for (tk::Observer* obs : tk::g_state->map->get_observers_manual_lock())
            {
                if (obs->type == tk::Observer::ObserverType::Self)
                {
                    continue;
                }

                int r = 255;
                int g = 255;
                int b = 255;

                if (auto entry = s_group_map.find(obs->group_id); entry != std::end(s_group_map))
                {
                    r = std::get<0>(entry->second);
                    g = std::get<1>(entry->second);
                    b = std::get<2>(entry->second);
                }

                glm::vec3 player_pos(player->pos.x, player->pos.y, player->pos.z);
                glm::vec3 obs_pos(obs->pos.x, obs->pos.y, obs->pos.z);
                draw_text(obs->pos.x, obs->pos.y + 3.0f, obs->pos.z, 0.25f, std::to_string((int)glm::length(obs_pos - player_pos)).c_str(), r, g, b, get_alpha_for_y(player_y, obs->pos.y), &view, &projection);
                draw_text(obs->pos.x, obs->pos.y + 2.0f, obs->pos.z, 0.05f, obs->name.c_str(), r, g, b, get_alpha_for_y(player_y, obs->pos.y), &view, &projection);
            }

            for (auto& [pos, txt] : loot_text_to_render)
            {
                draw_text(pos.x, pos.y + 0.5f, pos.z, 0.05f, txt.c_str(), 255, 215, 0, get_alpha_for_y(player_y, pos.y), &view, &projection);
            }
        }

        tk::g_state->map->unlock();
    }
    }

    SDL_GL_SwapWindow(gfx->window);
    SDL_Delay(33);
}

GraphicsState make_gfx(SDL_GLContext ctx, SDL_Window* window)
{
    gltInit();

    GraphicsState gfx;
    gfx.ctx = ctx;
    gfx.window = window;
    gfx.shader = glCreateProgram();

    auto make_shader = [](GLuint type, const char* shader) -> GLuint
    {
        GLuint handle = glCreateShader(type);
        glShaderSource(handle, 1, &shader, NULL);
        glCompileShader(handle);

        int success;
        glGetShaderiv(handle, GL_COMPILE_STATUS, &success);
        if (!success)
        {
            char info[512];
            glGetShaderInfoLog(handle, 512, NULL, info);
        };

        return handle;
    };
  
    GLuint vtx_shader = make_shader(GL_VERTEX_SHADER,
        R"(
            #version 330 core
            layout (location = 0) in vec3 aPos;
            layout (location = 1) in vec2 aTexCoord;

            out float Alpha;

            uniform mat4 model;
            uniform mat4 view;
            uniform mat4 projection;
            uniform int line;
            uniform float player_y;
            uniform float obj_y;

            void main()
            {
                if (line > 0)
                {
                    gl_Position = projection * view * vec4(aPos, 1.0f);
                    Alpha = line / 255.0f;
                }
                else
                {
                    gl_Position = projection * view * model * vec4(aPos, 1.0f);
                    Alpha = abs(player_y - obj_y) >= 3.0f ? 0.25f : 1.0f;
                }
            }
        )"
    );  

    GLuint pixel_shader = make_shader(GL_FRAGMENT_SHADER,
        R"(
            #version 330 core
            out vec4 FragColor;

            in float Alpha;

            uniform vec3 color;

            void main()
            {
                FragColor = vec4(color, Alpha);
            }
        )"
    );

    glAttachShader(gfx.shader, vtx_shader);
    glAttachShader(gfx.shader, pixel_shader);
    glLinkProgram(gfx.shader);

    float vertices[] = {
        -0.5f, -0.5f, -0.5f,  0.0f, 0.0f,
         0.5f, -0.5f, -0.5f,  1.0f, 0.0f,
         0.5f,  0.5f, -0.5f,  1.0f, 1.0f,
         0.5f,  0.5f, -0.5f,  1.0f, 1.0f,
        -0.5f,  0.5f, -0.5f,  0.0f, 1.0f,
        -0.5f, -0.5f, -0.5f,  0.0f, 0.0f,

        -0.5f, -0.5f,  0.5f,  0.0f, 0.0f,
         0.5f, -0.5f,  0.5f,  1.0f, 0.0f,
         0.5f,  0.5f,  0.5f,  1.0f, 1.0f,
         0.5f,  0.5f,  0.5f,  1.0f, 1.0f,
        -0.5f,  0.5f,  0.5f,  0.0f, 1.0f,
        -0.5f, -0.5f,  0.5f,  0.0f, 0.0f,

        -0.5f,  0.5f,  0.5f,  1.0f, 0.0f,
        -0.5f,  0.5f, -0.5f,  1.0f, 1.0f,
        -0.5f, -0.5f, -0.5f,  0.0f, 1.0f,
        -0.5f, -0.5f, -0.5f,  0.0f, 1.0f,
        -0.5f, -0.5f,  0.5f,  0.0f, 0.0f,
        -0.5f,  0.5f,  0.5f,  1.0f, 0.0f,

         0.5f,  0.5f,  0.5f,  1.0f, 0.0f,
         0.5f,  0.5f, -0.5f,  1.0f, 1.0f,
         0.5f, -0.5f, -0.5f,  0.0f, 1.0f,
         0.5f, -0.5f, -0.5f,  0.0f, 1.0f,
         0.5f, -0.5f,  0.5f,  0.0f, 0.0f,
         0.5f,  0.5f,  0.5f,  1.0f, 0.0f,

        -0.5f, -0.5f, -0.5f,  0.0f, 1.0f,
         0.5f, -0.5f, -0.5f,  1.0f, 1.0f,
         0.5f, -0.5f,  0.5f,  1.0f, 0.0f,
         0.5f, -0.5f,  0.5f,  1.0f, 0.0f,
        -0.5f, -0.5f,  0.5f,  0.0f, 0.0f,
        -0.5f, -0.5f, -0.5f,  0.0f, 1.0f,

        -0.5f,  0.5f, -0.5f,  0.0f, 1.0f,
         0.5f,  0.5f, -0.5f,  1.0f, 1.0f,
         0.5f,  0.5f,  0.5f,  1.0f, 0.0f,
         0.5f,  0.5f,  0.5f,  1.0f, 0.0f,
        -0.5f,  0.5f,  0.5f,  0.0f, 0.0f,
        -0.5f,  0.5f, -0.5f,  0.0f, 1.0f
    };

    glGenVertexArrays(1, &gfx.vao);
    glGenBuffers(1, &gfx.vbo);
    glBindVertexArray(gfx.vao);
    glBindBuffer(GL_ARRAY_BUFFER, gfx.vbo);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);
    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 5 * sizeof(float), (void*)0);
    glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 5 * sizeof(float), (void*)(3 * sizeof(float)));
    glEnableVertexAttribArray(0);
    glEnableVertexAttribArray(1);

    glGenVertexArrays(1, &gfx.line_vao);
    glGenBuffers(1, &gfx.line_vbo);
    glBindVertexArray(gfx.line_vao);
    glBindBuffer(GL_ARRAY_BUFFER, gfx.line_vbo);
    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(float), (void*)0);
    glEnableVertexAttribArray(0);

    glEnable(GL_DEPTH_TEST);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    int width;
    int height;
    SDL_GetWindowSize(gfx.window, &width, &height);
    resize_gfx(&gfx, width, height);

    return gfx;
}

void resize_gfx(GraphicsState* state, int width, int height)
{
    glViewport(0, 0, width, height);
    state->width = width;
    state->height = height;
}

//definition of EFTRadarSetup()
void EFTRadarSettup() {
    const unsigned long puffer_size = 255;
    char puffer[puffer_size];
    char ini[] = "./EFTRadarSettings.ini";

    //Read IP_RADAR_PC from EFTRadarSettings.ini
    GetPrivateProfileString("RadarSettings", "IP_RADAR_PC", "error", puffer, puffer_size, ini);
    DEVICE_IP_RADAR_PC = puffer;

    if (DEVICE_IP_RADAR_PC == "fill.me.in.with.the.local.network.adapter.ip.of.radar.pc")
    {
        std::cout << "IP_RADAR_PC not set in EFTRadarSettings.ini\n";
        std::cout << "Press ENTER to exit \n";
        std::cin.ignore();
        exit(1);
    }

    //Read IP_GAME_PC from EFTRadarSettings.ini
    GetPrivateProfileString("RadarSettings", "IP_GAME_PC", "error", puffer, puffer_size, ini);
    DEVICE_IP_GAME_PC = puffer;

    if (DEVICE_IP_GAME_PC == "fill.me.in.with.the.vpn.adapter.ip.of.game.pc")
    {
        std::cout << "IP_GAME_PC not set in EFTRadarSettings.ini\n";
        std::cout << "Press ENTER to exit \n";
        std::cin.ignore();
        exit(1);
    }

    //Read if Transparent from EFTRadarSettings.ini
    GetPrivateProfileString("RadarSettings", "bg_transparent", "error", puffer, puffer_size, ini);
    std::string tmp = puffer;

    if (tmp == "true") {
        background_Transparent = true;
    }
    else {
        background_Transparent = false;
    }

    //Read if custom_colour from EFTRadarSettings.ini
    GetPrivateProfileString("RadarSettings", "custom_bg_colour", "error", puffer, puffer_size, ini);
    tmp = puffer;

    if (tmp == "true") {
        custom_bg_colour = true;
        custom_r = GetPrivateProfileInt("RadarSettings", "custom_r", 0, ini);
        custom_g = GetPrivateProfileInt("RadarSettings", "custom_g", 0, ini);
        custom_b = GetPrivateProfileInt("RadarSettings", "custom_b", 0, ini);
    }
    else {
        custom_bg_colour = false;
    }

    //view mode: 0= fixed cam, 1= free cam, 2= top down fixed cam 3= top down free cam
    view_mode = GetPrivateProfileInt("RadarSettings", "view_mode", 0, ini);
    //set freecam depending on view_mode
    if (view_mode % 2 == 1) {
        freecam = true;
    }


    //print some stuff on console
    std::cout << "Set IPv4 address of Radar PC to: '" << DEVICE_IP_RADAR_PC.c_str() << "'\n";
    std::cout << "Set IPv4 address of Game PC to: '" << DEVICE_IP_GAME_PC.c_str() << "'\n";
    printviewmode(view_mode);
    std::cout << "Set Background Transparent: " << std::boolalpha << background_Transparent << "\n";
    std::cout << "Set Background Custom colour: " << std::boolalpha << custom_bg_colour << "\n";
    if (custom_bg_colour) {
        std::cout << "custom r: " << custom_r << std::endl;
        std::cout << "custom g: " << custom_g << std::endl;
        std::cout << "custom b: " << custom_b << std::endl;
    }
    std::cout << "\n";
}

//Solution found at (https://stackoverflow.com/a/51956224)
bool MakeWindowTransparent(SDL_Window* window, COLORREF colorKey) {
    // Get window handle (https://stackoverflow.com/a/24118145/3357935)
    SDL_SysWMinfo wmInfo;
    SDL_VERSION(&wmInfo.version);  // Initialize wmInfo
    SDL_GetWindowWMInfo(window, &wmInfo);
    HWND hWnd = wmInfo.info.win.window;

    // Change window type to layered (https://stackoverflow.com/a/3970218/3357935)
    SetWindowLong(hWnd, GWL_EXSTYLE, GetWindowLong(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);

    // Set transparency color
    return SetLayeredWindowAttributes(hWnd, colorKey, 0, LWA_COLORKEY);
}

void printviewmode(int vm) {
    switch (vm) {
    case 0:
        std::cout << "view_mode number: 0 - 3D fixed cam\n";
        break;
    case 1:
        std::cout << "view_mode number: 1 - 3D free cam\n";
        break;
    case 2:
        std::cout << "view_mode number: 2 - 2D fixed cam\n";
        break;
    case 3:
        std::cout << "view_mode number: 3 - 2D free cam\n";
        break;

    default:
        std::cout << "view_mode incorrect number:" << view_mode << "\n";
        break;
    }
}

void switchTransparent() {
    background_Transparent = !background_Transparent;
}

void switchFreecam() {
    freecam = !freecam;
    if (freecam) {
        view_mode += 1;
    }
    else {
        view_mode -= 1;
    }
    printviewmode(view_mode);
}
void switchViewMode() {
    view_mode ++;
    freecam = !freecam;
    view_mode = view_mode % 4;
    printviewmode(view_mode);
}

void resetCamPos() {
        freecam_pos_x = topdown_freecam_pos_x = player_pos_x;
        freecam_pos_y = player_pos_y + 1.5f;
        freecam_pos_z = topdown_freecam_pos_z = player_pos_z;

}




/* Print all information about a key event */
void KeyController(SDL_KeyboardEvent* key) {
    /* Print the state + name of the key */
    if (key->type == SDL_KEYDOWN) {
        std::cout << "Pressed Key: " << SDL_GetKeyName(key->keysym.sym) << "\n";
        //do stuff with keys
        switch (key->keysym.sym) {
            //change camera height
        case SDLK_SPACE:
            if (view_mode > 1) {
                topdown_cam_height += movment_sensitivity;
                if (topdown_cam_height > 1000.0f) {
                    topdown_cam_height = 1000.0f;
                }
                std::cout << "2d cam new height: " << topdown_cam_height << "\n";
            }
            else {
                freecam_pos_y += movment_sensitivity;
                std::cout << "3d freecam new height: " << freecam_pos_y << "\n";
            }
            
            break;
        case SDLK_LSHIFT:
            if (view_mode > 1) {
                topdown_cam_height -= movment_sensitivity;
                if (topdown_cam_height < 5.0f) {
                    topdown_cam_height = 5.0f;
                }
                std::cout << "2d cam new height: " << topdown_cam_height << "\n";
            }
            else {
                freecam_pos_y -= movment_sensitivity;
                std::cout << "3d freecam new height: " << freecam_pos_y << "\n";
            }
            break;
        case SDLK_w:
            if (view_mode > 1) {
                freecam_pos_z += movment_sensitivity;
            }
            else {
                freecam_pos_x += player_forward_vec.x;
                freecam_pos_y += player_forward_vec.y;
                freecam_pos_z += player_forward_vec.z;
                std::cout << "3d freecam x " << player_forward_vec.x << "\n";
                std::cout << "3d freecam y: " << player_forward_vec.y << "\n";
                std::cout << "3d freecam z: " << player_forward_vec.z << "\n";
            }
            break;
        case SDLK_s:
            if (view_mode > 1) {
                freecam_pos_z -= movment_sensitivity;
            }
            else {
                freecam_pos_x -= player_forward_vec.x;
                freecam_pos_y -= player_forward_vec.y;
                freecam_pos_z -= player_forward_vec.z;
                std::cout << "3d freecam x " << player_forward_vec.x << "\n";
                std::cout << "3d freecam y: " << player_forward_vec.y << "\n";
                std::cout << "3d freecam z: " << player_forward_vec.z << "\n";
            }
            break;
        case SDLK_d:
            if (view_mode > 1) {
                freecam_pos_x += movment_sensitivity;
            }
            else {
                freecam_pos_x += getStrafeVectorRight(player_forward_vec).x;
                freecam_pos_z += getStrafeVectorRight(player_forward_vec).z;
            }
            break;
        case SDLK_a:
            if (view_mode > 1) {
                freecam_pos_x -= movment_sensitivity;
            }
            else {
                freecam_pos_x -= getStrafeVectorRight(player_forward_vec).x;
                freecam_pos_z -= getStrafeVectorRight(player_forward_vec).z;
            }
            break;

        case SDLK_t:
            switchTransparent();
            std::cout << "background_Transparent: " << background_Transparent << "\n";
            break;
        case SDLK_f:
            switchFreecam();
            std::cout << "freecam: " << freecam << "\n";
            break;
        case SDLK_r:
            resetCamPos();
            std::cout << "reset camera position" << "\n";
            break;
        case SDLK_v:
            switchViewMode();
            break;
        default:
            break;
        }
    }

}

glm::vec3 getStrafeVectorRight(glm::vec3 vec) {
    return glm::vec3(vec.x*0+vec.y*0+vec.z*1, vec.x * 0 + vec.y * 1 + vec.z * 0, vec.x * -1 + vec.y * 0 + vec.z * 0);
}